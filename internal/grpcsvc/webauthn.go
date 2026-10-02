// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"time"

	log "github.com/Bugs5382/go-log"
	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Passkey / WebAuthn. Identity is the Relying Party (go-webauthn). Options +
// credential payloads cross the wire as opaque JSON strings. Challenge state
// (go-webauthn SessionData) persists single-use in webauthn_sessions between a
// begin and its finish; credentials live in user_webauthn_credentials. This is
// identity's own login, never Keycloak: a first-class identity factor.

const (
	webauthnSessionTTL  = 5 * time.Minute
	webauthnLabelMaxLen = 120
	webauthnPurposeReg  = "register"
	webauthnPurposeAsrt = "assert"
)

func (s *Server) webauthnEnabled() error {
	if s.webauthn == nil {
		return status.Error(codes.Unavailable, "passkeys not configured")
	}
	return nil
}

// webauthnUser adapts a Sneakers user + its stored credentials to the go-webauthn
// User interface. WebAuthnID is the (short, stable) user id bytes.
type webauthnUser struct {
	id, name, email, username string
	creds                     []webauthn.Credential
}

func (w *webauthnUser) WebAuthnID() []byte { return []byte(w.id) }
func (w *webauthnUser) WebAuthnName() string {
	switch {
	case w.email != "":
		return w.email
	case w.username != "":
		return w.username
	default:
		return w.id
	}
}
func (w *webauthnUser) WebAuthnDisplayName() string {
	if w.name != "" {
		return w.name
	}
	return w.WebAuthnName()
}
func (w *webauthnUser) WebAuthnCredentials() []webauthn.Credential { return w.creds }

// webauthnUserFor loads the user + rehydrates their stored credentials.
func (s *Server) webauthnUserFor(ctx context.Context, userID string) (*webauthnUser, error) {
	wu := &webauthnUser{id: userID}
	err := s.db.QueryRow(ctx, `SELECT name, email, username FROM users WHERE id=$1`, userID).Scan(&wu.name, &wu.email, &wu.username)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, status.Error(codes.NotFound, "user not found")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "load user: %v", err)
	}
	rows, err := s.db.Query(ctx,
		`SELECT credential_id, public_key, sign_count, aaguid, transports, backup_eligible, backup_state
		   FROM user_webauthn_credentials WHERE user_id=$1`, userID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "load credentials: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			credID                      string
			pub, aaguid                 []byte
			signCount                   int64
			transports                  []string
			backupEligible, backupState bool
		)
		if err := rows.Scan(&credID, &pub, &signCount, &aaguid, &transports, &backupEligible, &backupState); err != nil {
			return nil, status.Errorf(codes.Internal, "scan credential: %v", err)
		}
		idBytes, derr := base64.RawURLEncoding.DecodeString(credID)
		if derr != nil {
			continue // skip a corrupt row rather than fail the whole ceremony
		}
		tr := make([]protocol.AuthenticatorTransport, 0, len(transports))
		for _, t := range transports {
			tr = append(tr, protocol.AuthenticatorTransport(t))
		}
		wu.creds = append(wu.creds, webauthn.Credential{
			ID:        idBytes,
			PublicKey: pub,
			Transport: tr,
			Flags:     webauthn.CredentialFlags{BackupEligible: backupEligible, BackupState: backupState},
			Authenticator: webauthn.Authenticator{
				AAGUID:    aaguid,
				SignCount: safeUint32(signCount),
			},
		})
	}
	return wu, rows.Err()
}

// safeUint32 narrows a stored int64 sign-count to uint32 with a bounds check
// (G115-safe — never a blind cast).
func safeUint32(v int64) uint32 {
	if v < 0 || v > math.MaxUint32 {
		return 0
	}
	return uint32(v)
}

func newWebauthnSessionID() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// beginSession persists the go-webauthn SessionData and returns its handle. A
// fresh begin supersedes the user's prior session for the same purpose, and
// expired rows are pruned.
func (s *Server) beginSession(ctx context.Context, userID, purpose string, data *webauthn.SessionData) (string, error) {
	blob, err := json.Marshal(data)
	if err != nil {
		return "", status.Errorf(codes.Internal, "marshal session: %v", err)
	}
	id, err := newWebauthnSessionID()
	if err != nil {
		return "", status.Errorf(codes.Internal, "session id: %v", err)
	}
	if _, err := s.db.Exec(ctx, `DELETE FROM webauthn_sessions WHERE (user_id=$1 AND purpose=$2) OR expires_at<now()`, userID, purpose); err != nil {
		return "", status.Errorf(codes.Internal, "prune sessions: %v", err)
	}
	if _, err := s.db.Exec(ctx,
		`INSERT INTO webauthn_sessions (session_id, user_id, purpose, data_json, expires_at) VALUES ($1,$2,$3,$4,$5)`,
		id, userID, purpose, string(blob), time.Now().Add(webauthnSessionTTL)); err != nil {
		return "", status.Errorf(codes.Internal, "store session: %v", err)
	}
	return id, nil
}

// consumeSession single-use fetches the SessionData (deleted whether or not the
// later verification succeeds). Unknown/wrong-user/wrong-purpose/expired all →
// NotFound.
func (s *Server) consumeSession(ctx context.Context, sessionID, userID, purpose string) (*webauthn.SessionData, error) {
	var blob string
	err := s.db.QueryRow(ctx,
		`DELETE FROM webauthn_sessions WHERE session_id=$1 AND user_id=$2 AND purpose=$3 AND expires_at>now() RETURNING data_json`,
		sessionID, userID, purpose).Scan(&blob)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, status.Error(codes.NotFound, "webauthn session not found or expired")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "consume session: %v", err)
	}
	var data webauthn.SessionData
	if err := json.Unmarshal([]byte(blob), &data); err != nil {
		return nil, status.Errorf(codes.Internal, "decode session: %v", err)
	}
	return &data, nil
}

// WebauthnRegisterBegin starts passkey enrollment for the user.
func (s *Server) WebauthnRegisterBegin(ctx context.Context, req *identityv1.WebauthnRegisterBeginRequest) (*identityv1.WebauthnRegisterBeginResponse, error) {
	if err := s.webauthnEnabled(); err != nil {
		return nil, err
	}
	wu, err := s.webauthnUserFor(ctx, req.GetUserId())
	if err != nil {
		return nil, err
	}
	excl := make([]protocol.CredentialDescriptor, 0, len(wu.creds))
	for _, c := range wu.creds {
		excl = append(excl, c.Descriptor())
	}
	options, session, err := s.webauthn.BeginRegistration(wu, webauthn.WithExclusions(excl))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "begin registration: %v", err)
	}
	sid, err := s.beginSession(ctx, req.GetUserId(), webauthnPurposeReg, session)
	if err != nil {
		return nil, err
	}
	blob, _ := json.Marshal(options)
	return &identityv1.WebauthnRegisterBeginResponse{OptionsJson: string(blob), SessionId: sid}, nil
}

// WebauthnRegisterFinish verifies + stores a freshly created passkey.
func (s *Server) WebauthnRegisterFinish(ctx context.Context, req *identityv1.WebauthnRegisterFinishRequest) (*identityv1.WebauthnRegisterFinishResponse, error) {
	if err := s.webauthnEnabled(); err != nil {
		return nil, err
	}
	if req.GetCredentialJson() == "" {
		return nil, status.Error(codes.InvalidArgument, "credential_json is required")
	}
	session, err := s.consumeSession(ctx, req.GetSessionId(), req.GetUserId(), webauthnPurposeReg)
	if err != nil {
		return nil, err
	}
	wu, err := s.webauthnUserFor(ctx, req.GetUserId())
	if err != nil {
		return nil, err
	}
	parsed, perr := protocol.ParseCredentialCreationResponseBytes([]byte(req.GetCredentialJson()))
	if perr != nil {
		return nil, status.Error(codes.InvalidArgument, "malformed credential")
	}
	cred, cerr := s.webauthn.CreateCredential(wu, *session, parsed)
	if cerr != nil {
		lg := log.Ctx(ctx)
		lg.Warn().Err(cerr).Msg("webauthn: credential verification failed")
		return nil, status.Error(codes.InvalidArgument, "credential verification failed")
	}
	label := req.GetLabel()
	if len(label) > webauthnLabelMaxLen {
		label = label[:webauthnLabelMaxLen]
	}
	transports := make([]string, 0, len(cred.Transport))
	for _, t := range cred.Transport {
		transports = append(transports, string(t))
	}
	credID := base64.RawURLEncoding.EncodeToString(cred.ID)
	_, err = s.db.Exec(ctx,
		`INSERT INTO user_webauthn_credentials
		   (credential_id, user_id, public_key, sign_count, aaguid, transports, backup_eligible, backup_state, label)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		credID, req.GetUserId(), cred.PublicKey, int64(cred.Authenticator.SignCount), cred.Authenticator.AAGUID,
		transports, cred.Flags.BackupEligible, cred.Flags.BackupState, label)
	if err != nil {
		return nil, status.Errorf(codes.AlreadyExists, "store credential: %v", err)
	}
	return &identityv1.WebauthnRegisterFinishResponse{}, nil
}

// WebauthnAssertBegin starts a passkey login challenge for the user.
func (s *Server) WebauthnAssertBegin(ctx context.Context, req *identityv1.WebauthnAssertBeginRequest) (*identityv1.WebauthnAssertBeginResponse, error) {
	if err := s.webauthnEnabled(); err != nil {
		return nil, err
	}
	wu, err := s.webauthnUserFor(ctx, req.GetUserId())
	if err != nil {
		return nil, err
	}
	if len(wu.creds) == 0 {
		return nil, status.Error(codes.FailedPrecondition, "no passkeys enrolled")
	}
	uv := protocol.VerificationPreferred
	if s.webauthn.Config.AuthenticatorSelection.UserVerification != "" {
		uv = s.webauthn.Config.AuthenticatorSelection.UserVerification
	}
	options, session, err := s.webauthn.BeginLogin(wu, webauthn.WithUserVerification(uv))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "begin login: %v", err)
	}
	sid, err := s.beginSession(ctx, req.GetUserId(), webauthnPurposeAsrt, session)
	if err != nil {
		return nil, err
	}
	blob, _ := json.Marshal(options)
	return &identityv1.WebauthnAssertBeginResponse{OptionsJson: string(blob), SessionId: sid}, nil
}

// WebauthnAssertFinish verifies a passkey assertion. ok=false covers a failed
// assertion or a sign-count regression (cloned authenticator); it never advances
// the counter on failure.
func (s *Server) WebauthnAssertFinish(ctx context.Context, req *identityv1.WebauthnAssertFinishRequest) (*identityv1.WebauthnAssertFinishResponse, error) {
	if err := s.webauthnEnabled(); err != nil {
		return nil, err
	}
	session, err := s.consumeSession(ctx, req.GetSessionId(), req.GetUserId(), webauthnPurposeAsrt)
	if err != nil {
		return nil, err
	}
	wu, err := s.webauthnUserFor(ctx, req.GetUserId())
	if err != nil {
		return nil, err
	}
	parsed, perr := protocol.ParseCredentialRequestResponseBytes([]byte(req.GetCredentialJson()))
	if perr != nil {
		return &identityv1.WebauthnAssertFinishResponse{Ok: false}, nil
	}
	cred, verr := s.webauthn.ValidateLogin(wu, *session, parsed)
	if verr != nil {
		lg := log.Ctx(ctx)
		lg.Info().Err(verr).Msg("webauthn: assertion failed")
		return &identityv1.WebauthnAssertFinishResponse{Ok: false}, nil
	}
	// Anti-clone: a used authenticator's counter must strictly advance (unless
	// both are zero, which some authenticators use). CloneWarning is fatal.
	credID := base64.RawURLEncoding.EncodeToString(cred.ID)
	var stored int64
	if err := s.db.QueryRow(ctx, `SELECT sign_count FROM user_webauthn_credentials WHERE credential_id=$1 AND user_id=$2`,
		credID, req.GetUserId()).Scan(&stored); err != nil {
		return &identityv1.WebauthnAssertFinishResponse{Ok: false}, nil
	}
	latest := int64(cred.Authenticator.SignCount)
	if cred.Authenticator.CloneWarning || ((stored != 0 || latest != 0) && latest <= stored) {
		lg := log.Ctx(ctx)
		lg.Warn().Str("credential", credID).Msg("webauthn: sign-count regression / clone warning")
		return &identityv1.WebauthnAssertFinishResponse{Ok: false}, nil
	}
	_, _ = s.db.Exec(ctx, `UPDATE user_webauthn_credentials SET sign_count=$3, last_used_at=now() WHERE credential_id=$1 AND user_id=$2`,
		credID, req.GetUserId(), latest)
	return &identityv1.WebauthnAssertFinishResponse{Ok: true}, nil
}

// ListWebauthnCredentials returns the user's enrolled passkeys (works without RP
// config — plain store read).
func (s *Server) ListWebauthnCredentials(ctx context.Context, req *identityv1.ListWebauthnCredentialsRequest) (*identityv1.ListWebauthnCredentialsResponse, error) {
	rows, err := s.db.Query(ctx,
		`SELECT credential_id, label, created_at, last_used_at, transports
		   FROM user_webauthn_credentials WHERE user_id=$1 ORDER BY created_at`, req.GetUserId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list credentials: %v", err)
	}
	defer rows.Close()
	out := &identityv1.ListWebauthnCredentialsResponse{}
	for rows.Next() {
		var (
			id, label  string
			created    time.Time
			lastUsed   *time.Time
			transports []string
		)
		if err := rows.Scan(&id, &label, &created, &lastUsed, &transports); err != nil {
			return nil, status.Errorf(codes.Internal, "scan credential: %v", err)
		}
		wc := &identityv1.WebauthnCredential{Id: id, Label: label, CreatedAt: created.UTC().Format(time.RFC3339), Transports: transports}
		if lastUsed != nil {
			wc.LastUsedAt = lastUsed.UTC().Format(time.RFC3339)
		}
		out.Credentials = append(out.Credentials, wc)
	}
	return out, rows.Err()
}

// RemoveWebauthnCredential deletes one of the user's passkeys.
func (s *Server) RemoveWebauthnCredential(ctx context.Context, req *identityv1.RemoveWebauthnCredentialRequest) (*identityv1.RemoveWebauthnCredentialResponse, error) {
	tag, err := s.db.Exec(ctx, `DELETE FROM user_webauthn_credentials WHERE user_id=$1 AND credential_id=$2`,
		req.GetUserId(), req.GetCredentialId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "remove credential: %v", err)
	}
	if tag.RowsAffected() == 0 {
		return nil, status.Error(codes.NotFound, "credential not found")
	}
	return &identityv1.RemoveWebauthnCredentialResponse{}, nil
}
