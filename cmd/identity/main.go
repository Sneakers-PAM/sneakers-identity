// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"os/signal"
	"strings"
	"syscall"

	log "github.com/Bugs5382/go-log"
	otel "github.com/Bugs5382/go-otel"
	postgres "github.com/Bugs5382/go-postgres"
	otelpg "github.com/Bugs5382/go-postgres/otel"
	auditv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/thirdparty/audit/v1"
	"github.com/Sneakers-PAM/sneakers-identity/internal/audit"
	"github.com/Sneakers-PAM/sneakers-identity/internal/config"
	"github.com/Sneakers-PAM/sneakers-identity/internal/email"
	"github.com/Sneakers-PAM/sneakers-identity/internal/grpcsvc"
	"github.com/Sneakers-PAM/sneakers-identity/internal/health"
	"github.com/Sneakers-PAM/sneakers-identity/internal/kratos"
	"github.com/Sneakers-PAM/sneakers-identity/internal/secrets"
	"github.com/Sneakers-PAM/sneakers-identity/internal/server"
	"github.com/Sneakers-PAM/sneakers-identity/internal/workloadauth"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

const serviceName = "identity"

func getOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() { //nolint:gocognit,gocyclo // wiring/bootstrap complexity
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger := log.New(serviceName)
	cfg, err := config.Load()
	if err != nil {
		logger.Fatal().Err(err).Msg("config")
	}

	otelShutdown, err := otel.Init(ctx, serviceName, cfg.OTLPEndpoint)
	if err != nil {
		logger.Fatal().Err(err).Msg("otel init")
	}
	defer func() {
		if err := otelShutdown(context.Background()); err != nil {
			logger.Warn().Err(err).Msg("otel shutdown")
		}
	}()

	migrationsDir := os.Getenv("MIGRATIONS_DIR")
	if migrationsDir == "" {
		migrationsDir = "migrations"
	}
	// Migrations need a direct/session Postgres connection (advisory locks,
	// CURRENT_SCHEMA, prepared statements) which break through a
	// transaction-pooling connection pooler at runtime. Use MIGRATE_DSN when set,
	// otherwise fall back to the pooled runtime DSN.
	migrateDSN := os.Getenv("MIGRATE_DSN")
	if migrateDSN == "" {
		migrateDSN = cfg.DatabaseDSN
	}
	if err := postgres.Migrate(migrateDSN, migrationsDir); err != nil {
		logger.Fatal().Err(err).Msg("migrate")
	}
	db, err := postgres.New(ctx, cfg.DatabaseDSN, otelpg.WithTracing())
	if err != nil {
		logger.Fatal().Err(err).Msg("db connect")
	}
	defer db.Close()
	if err := server.RecordPostgresVersion(ctx, db.Querier()); err != nil {
		logger.Warn().Err(err).Msg("postgres version unknown; the health check won't report it")
	}

	// Demo directory seeding lives in the dev/qa-only `cmd/seed` tool (go-seed),
	// not in the service.

	// MFA at-rest cipher for the TOTP shared secret. TOTP_ENC_KEY is 32 bytes as
	// hex or std-base64; when unset the TOTP RPCs report Unavailable (feature not
	// configured) rather than storing secrets in the clear — fail closed.
	var cipher *secrets.Cipher
	if key := os.Getenv("TOTP_ENC_KEY"); key != "" {
		cipher, err = secrets.NewFromString(key)
		if err != nil {
			logger.Fatal().Err(err).Msg("totp enc key")
		}
		logger.Info().Msg("mfa: TOTP enabled (at-rest cipher configured)")
	} else {
		logger.Warn().Msg("mfa: TOTP disabled (TOTP_ENC_KEY unset)")
	}

	// MFA email OTP. Wire the SMTP relay only when SMTP_HOST is set
	// (prod / a maildev dev box); otherwise the code is still minted and, with
	// OTP_DEV_ECHO, logged for local testing — no relay required. OTP_DEV_ECHO is
	// a dev-only ergonomic and must never be enabled in prod.
	var sender email.Sender
	if os.Getenv("SMTP_HOST") != "" {
		sender = email.New(email.LoadConfig())
		logger.Info().Msg("mfa: email OTP relay configured (SMTP_HOST)")
	} else {
		logger.Warn().Msg("mfa: email OTP relay not configured (SMTP_HOST unset) — codes are dev-echoed only when OTP_DEV_ECHO=1")
	}
	devEcho := os.Getenv("OTP_DEV_ECHO") == "1" || os.Getenv("OTP_DEV_ECHO") == "true"

	// Passkey/WebAuthn Relying Party. Disabled when WEBAUTHN_RP_ID is unset
	// or "-"; then the ceremony RPCs report Unavailable but list/remove still work.
	// WebAuthn requires a secure context in the browser — verify on an HTTPS edge.
	var wa *webauthn.WebAuthn
	if rpID := getOr("WEBAUTHN_RP_ID", "localhost"); rpID != "-" {
		origins := []string{}
		for _, o := range strings.Split(getOr("WEBAUTHN_RP_ORIGINS", "http://localhost:8095"), ",") {
			if t := strings.TrimSpace(o); t != "" {
				origins = append(origins, t)
			}
		}
		w, werr := webauthn.New(&webauthn.Config{
			RPID:          rpID,
			RPDisplayName: getOr("WEBAUTHN_RP_NAME", "Sneakers"),
			RPOrigins:     origins,
			AuthenticatorSelection: protocol.AuthenticatorSelection{
				UserVerification: protocol.UserVerificationRequirement(getOr("WEBAUTHN_USER_VERIFICATION", "preferred")),
			},
		})
		if werr != nil {
			logger.Warn().Err(werr).Msg("webauthn: RP config invalid — passkeys disabled")
		} else {
			wa = w
			logger.Info().Str("rp_id", rpID).Msg("webauthn: passkey RP configured")
		}
	} else {
		logger.Warn().Msg("webauthn: disabled (WEBAUTHN_RP_ID unset/'-')")
	}

	svcLog := log.NewLogger(serviceName)
	// Ory Kratos holds the credentials: users are provisioned as Kratos
	// identities and their row stores the identity id as the login subject.
	adminURL := getOr("KRATOS_ADMIN_URL", "http://sneakers-kratos:4434")
	kratosAdmin := kratos.NewAdmin(adminURL)
	srv := grpcsvc.New(db).WithLogger(svcLog).WithCipher(cipher).WithEmail(sender, devEcho).
		WithTotpIssuer(getOr("TOTP_ISSUER", "Sneakers")).WithWebauthn(wa).
		WithKratos(kratosAdmin)

	// Readiness: Postgres holds the directory and Kratos the credentials, so
	// identity can't serve without either. Audit records are best effort, so
	// an unreachable audit service only degrades it.
	deps := []health.Dep{
		{Name: "postgres", Required: true, Check: db.Ping},
		{Name: "kratos", Required: true, Check: kratosAdmin.Ready},
	}

	// Audit: sign-ins, second factors and every user, group, role, service
	// account and token change are recorded in the audit service.
	if cfg.AuditAddr != "" {
		dialOpts := []grpc.DialOption{
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithStatsHandler(otelgrpc.NewClientHandler()),
		}
		// The audit service authenticates identity by its projected
		// ServiceAccount token, re-read from WORKLOAD_TOKEN_FILE on every call.
		tokenOpt, ok, err := workloadauth.DialOptionFromEnv(os.Getenv)
		if err != nil {
			logger.Fatal().Err(err).Msg("workload token")
		}
		if ok {
			dialOpts = append(dialOpts, tokenOpt)
			logger.Info().Str("env", workloadauth.EnvTokenFile).Msg("audit: calls carry the workload token")
		} else {
			logger.Warn().Msg("audit: " + workloadauth.EnvTokenFile + " unset; calls carry no workload token (local development only)")
		}
		auditConn, err := grpc.NewClient(cfg.AuditAddr, dialOpts...)
		if err != nil {
			logger.Fatal().Err(err).Str("audit_addr", cfg.AuditAddr).Msg("dial audit")
		}
		defer func() { _ = auditConn.Close() }()
		srv = srv.WithAudit(audit.NewClient(auditv1.NewAuditServiceClient(auditConn)))
		deps = append(deps, health.Dep{Name: "audit", Check: health.GRPCPeer(healthpb.NewHealthClient(auditConn))})
		logger.Info().Str("audit_addr", cfg.AuditAddr).Msg("audit: recording identity events")
	} else {
		logger.Warn().Msg("audit: disabled (AUDIT_ADDR unset); no identity events are recorded")
	}
	logger.Info().Str("kratos_admin_url", adminURL).Msg("user directory: kratos")

	logger.Info().Str("port", cfg.GRPCPort).Msg("starting")
	// Callers are authenticated by their workload identity and checked against
	// grpcsvc.CallerPolicy: the gateway on every method, notify on its reads.
	var serverOpts []grpc.ServerOption
	waCfg, waOn, err := workloadauth.ServerConfigFromEnv(os.Getenv)
	if err != nil {
		logger.Fatal().Err(err).Msg("workload auth")
	}
	if waOn {
		verifier, err := workloadauth.NewVerifier(waCfg, svcLog)
		if err != nil {
			logger.Fatal().Err(err).Msg("workload auth verifier")
		}
		go verifier.Run(ctx)
		policy := grpcsvc.CallerPolicy()
		serverOpts = append(serverOpts,
			grpc.ChainUnaryInterceptor(workloadauth.UnaryServerInterceptor(verifier, policy, svcLog, workloadauth.WithDenyHook(srv.AuditDenial))),
			grpc.ChainStreamInterceptor(workloadauth.StreamServerInterceptor(verifier, policy, svcLog, workloadauth.WithDenyHook(srv.AuditDenial))))
		logger.Info().Str("issuer", waCfg.Issuer).Strs("allowed_service_accounts", waCfg.AllowedServiceAccounts).Msg("workload auth: on")
	} else {
		go workloadauth.WarnDisabled(ctx, svcLog, workloadauth.DisabledWarnInterval)
	}

	checker := health.New(svcLog, deps)
	if err := server.RunWithHealth(ctx, cfg.GRPCPort, svcLog, checker, srv.RegisterOn, serverOpts...); err != nil {
		logger.Fatal().Err(err).Msg("server exited")
	}
}
