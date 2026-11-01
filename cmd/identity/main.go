// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	workloadauth "github.com/Bugs5382/go-workload-identity"
	auditv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/thirdparty/audit/v1"
	"github.com/Sneakers-PAM/sneakers-identity/internal/audit"
	"github.com/Sneakers-PAM/sneakers-identity/internal/config"
	"github.com/Sneakers-PAM/sneakers-identity/internal/email"
	"github.com/Sneakers-PAM/sneakers-identity/internal/grpcsvc"
	"github.com/Sneakers-PAM/sneakers-identity/internal/kratos"
	"github.com/Sneakers-PAM/sneakers-identity/internal/secrets"
	"github.com/Sneakers-PAM/sneakers-identity/internal/server"
	"github.com/Sneakers-PAM/sneakers-identity/internal/telemetry"
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

	logger := telemetry.NewLogger(serviceName, config.OTLPLogsEnabled())
	cfg, err := config.Load()
	if err != nil {
		logger.Fatal(err, "config")
	}

	otelSettings := telemetry.Settings{Endpoint: cfg.OTLPEndpoint, InsecureSkipVerify: cfg.OTLPInsecureSkipVerify, Logs: cfg.OTLPLogsEnabled}
	otelShutdown, err := telemetry.Start(ctx, serviceName, otelSettings)
	if err != nil {
		logger.Fatal(err, "otel init")
	}
	defer func() {
		if err := otelShutdown(context.Background()); err != nil {
			logger.Warn("otel shutdown", log.F("error", err.Error()))
		}
	}()

	// The port answers health from here on, while the boot waits for
	// Postgres and runs the migrations: liveness SERVING, so the startup probe
	// passes on a slow boot, and readiness NOT_SERVING with postgres listed
	// down until it is reached.
	boot, err := server.StartBootHealth(cfg.GRPCPort, logger, "postgres")
	if err != nil {
		logger.Fatal(err, "boot health")
	}

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
	db, err := openPostgres(ctx, boot, migrateDSN, migrationsDir, cfg.DatabaseDSN)
	if err != nil {
		if ctx.Err() != nil {
			boot.Stop()
			logger.Info("stopped while waiting for postgres")
			return
		}
		logger.Fatal(err, "postgres")
	}
	defer db.Close()

	// Demo directory seeding lives in the dev/qa-only `cmd/seed` tool (go-seed),
	// not in the service.

	// MFA at-rest cipher for the TOTP shared secret. TOTP_ENC_KEY is 32 bytes as
	// hex or std-base64; when unset the TOTP RPCs report Unavailable (feature not
	// configured) rather than storing secrets in the clear — fail closed.
	var cipher *secrets.Cipher
	if key := os.Getenv("TOTP_ENC_KEY"); key != "" {
		cipher, err = secrets.NewFromString(key)
		if err != nil {
			logger.Fatal(err, "totp enc key")
		}
		logger.Info("mfa: TOTP enabled (at-rest cipher configured)")
	} else {
		logger.Warn("mfa: TOTP disabled (TOTP_ENC_KEY unset)")
	}

	// MFA email OTP. Wire the SMTP relay only when SMTP_HOST is set
	// (prod / a maildev dev box); otherwise the code is still minted and, with
	// OTP_DEV_ECHO, logged for local testing — no relay required. OTP_DEV_ECHO is
	// a dev-only ergonomic and must never be enabled in prod.
	var sender email.Sender
	if os.Getenv("SMTP_HOST") != "" {
		cfg := email.LoadConfig()
		if err := cfg.Check(); err != nil {
			logger.Fatal(err, "smtp relay")
		}
		sender = email.New(cfg)
		logger.Info("mfa: email OTP relay configured (SMTP_HOST)", log.F("tls_mode", cfg.TLSMode), log.F("verify", !cfg.TLSInsecure),
			log.F("custom_ca", cfg.CAPEM != ""), log.F("auth", cfg.User != ""))
		if !cfg.Encrypted() || cfg.TLSInsecure {
			logger.Warn("smtp: mail, and the relay password when one is set, go to the relay unencrypted or to an unverified relay",
				log.F("tls_mode", cfg.TLSMode), log.F("verify", !cfg.TLSInsecure))
		}
	} else {
		logger.Warn("mfa: email OTP relay not configured (SMTP_HOST unset) — codes are dev-echoed only when OTP_DEV_ECHO=1")
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
			logger.Warn("webauthn: RP config invalid — passkeys disabled", log.F("error", werr.Error()))
		} else {
			wa = w
			logger.Info("webauthn: passkey RP configured", log.F("rp_id", rpID))
		}
	} else {
		logger.Warn("webauthn: disabled (WEBAUTHN_RP_ID unset/'-')")
	}

	// Ory Kratos holds the credentials: users are provisioned as Kratos
	// identities and their row stores the identity id as the login subject.
	adminURL := getOr("KRATOS_ADMIN_URL", "http://sneakers-kratos:4434")
	kratosAdmin := kratos.NewAdmin(adminURL)
	srv := grpcsvc.New(db).WithLogger(logger).WithCipher(cipher).WithEmail(sender, devEcho).
		WithTotpIssuer(getOr("TOTP_ISSUER", "Sneakers")).WithWebauthn(wa).
		WithKratos(kratosAdmin)

	// Readiness: Postgres holds the directory and Kratos the credentials, so
	// identity can't serve without either. Audit records are best effort, so
	// an unreachable audit service only degrades it.
	deps := []health.Dependency{
		{Name: "postgres", Required: true, Check: db.Ping, Version: server.PostgresVersion(db.Querier())},
		{Name: "kratos", Required: true, Check: kratosAdmin.Ready},
	}
	deps = append(deps, telemetry.Dependencies(otelSettings)...)

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
			logger.Fatal(err, "workload token")
		}
		if ok {
			dialOpts = append(dialOpts, tokenOpt)
			logger.Info("audit: calls carry the workload token", log.F("env", workloadauth.EnvTokenFile))
		} else {
			logger.Warn("audit: " + workloadauth.EnvTokenFile + " unset; calls carry no workload token (local development only)")
		}
		auditConn, err := grpc.NewClient(cfg.AuditAddr, dialOpts...)
		if err != nil {
			logger.Fatal(err, "dial audit", log.F("audit_addr", cfg.AuditAddr))
		}
		defer func() { _ = auditConn.Close() }()
		srv = srv.WithAudit(audit.NewClient(auditv1.NewAuditServiceClient(auditConn)))
		deps = append(deps, health.Dependency{Name: "audit", Check: server.GRPCPeer(healthpb.NewHealthClient(auditConn))})
		logger.Info("audit: recording identity events", log.F("audit_addr", cfg.AuditAddr))
	} else {
		logger.Warn("audit: disabled (AUDIT_ADDR unset); no identity events are recorded")
	}
	logger.Info("user directory: kratos", log.F("kratos_admin_url", adminURL))

	logger.Info("starting", log.F("port", cfg.GRPCPort))
	// Callers are authenticated by their workload identity and checked against
	// grpcsvc.CallerPolicy: the gateway on every method, notify on its reads.
	var serverOpts []grpc.ServerOption
	waCfg, waOn, err := server.WorkloadConfigFromEnv(os.Getenv)
	if err != nil {
		logger.Fatal(err, "workload auth")
	}
	if waOn {
		verifier, err := workloadauth.NewVerifier(waCfg, logger)
		if err != nil {
			logger.Fatal(err, "workload auth verifier")
		}
		go verifier.Run(ctx)
		policy := grpcsvc.CallerPolicy()
		serverOpts = append(serverOpts,
			grpc.ChainUnaryInterceptor(workloadauth.UnaryServerInterceptor(verifier, policy, logger, workloadauth.WithDenyHook(srv.AuditDenial))),
			grpc.ChainStreamInterceptor(workloadauth.StreamServerInterceptor(verifier, policy, logger, workloadauth.WithDenyHook(srv.AuditDenial))))
		// No caller can be checked before the issuer's key set has loaded, so
		// readiness waits for it too (see server.WorkloadIdentity).
		deps = append(deps, server.WorkloadIdentity(verifier))
		logger.Info("workload auth: on", log.F("issuer", waCfg.Issuer), log.F("allowed_service_accounts", waCfg.AllowedServiceAccounts))
	} else {
		go workloadauth.WarnDisabled(ctx, logger, workloadauth.DisabledWarnInterval)
	}

	checker, err := server.NewChecker(logger, deps)
	if err != nil {
		logger.Fatal(err, "health checker")
	}
	boot.Stop()
	if err := server.RunWithHealth(ctx, cfg.GRPCPort, logger, checker, srv.RegisterOn, serverOpts...); err != nil {
		logger.Fatal(err, "server exited")
	}
}
