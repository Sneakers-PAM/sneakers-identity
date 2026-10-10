// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package email is a tiny env-driven SMTP sender used by the OTP flows (the MFA
// email second factor, password reset and email verification). In dev it
// targets the maildev catcher (maildev:1025, no auth, no TLS); in prod SMTP_*
// point at a real relay.
//
// The sender is deliberately minimal: plaintext messages over net/smtp. The
// connection is plain, upgraded with STARTTLS, or TLS from the first byte
// (SMTP_TLS_MODE), and AUTH (PLAIN, else LOGIN) is used only when SMTP_USER is
// set. This matches the maildev default (no auth, plaintext) so a fresh dev box
// works with zero config.
package email

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The connection's TLS modes (SMTP_TLS_MODE).
const (
	// ModeNone sends in the clear, the credentials too.
	ModeNone = "none"
	// ModeStartTLS upgrades the connection with STARTTLS before AUTH and
	// refuses a relay that doesn't offer it.
	ModeStartTLS = "starttls"
	// ModeTLS speaks TLS from the first byte (implicit TLS, usually port 465).
	ModeTLS = "tls"
)

// timeout bounds one message: the dial and the whole conversation.
const timeout = 30 * time.Second

// Config is the resolved SMTP configuration. Build it with LoadConfig, which
// reads SMTP_* from the environment with maildev-friendly defaults.
type Config struct {
	Host string // SMTP_HOST (default "localhost")
	Port int    // SMTP_PORT (default 1025)
	User string // SMTP_USER (default "" — maildev needs no auth)
	Pass string // SMTP_PASS (default "")
	From string // SMTP_FROM (default "no-reply@example.org")
	// TLSMode is none, starttls or tls (SMTP_TLS_MODE). Unset, SMTP_TLS=true
	// means starttls and anything else none.
	TLSMode string
	// TLSInsecure skips the relay's certificate verification (SMTP_TLS_INSECURE,
	// default false). For a relay whose cert uses a legacy CN with no SANs
	// (Go 1.15+ rejects it): the connection is still encrypted, just not
	// cert-verified. Only set true for a trusted internal relay.
	TLSInsecure bool
	// CAPEM is one or more PEM certificates (SMTP_CA_PEM) trusted for the
	// relay, on top of the system roots.
	CAPEM string
}

// LoadConfig reads SMTP_* env vars with dev (maildev) defaults.
func LoadConfig() Config {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("SMTP_TLS_MODE")))
	if mode == "" {
		mode = ModeNone
		if getBoolOr("SMTP_TLS", false) {
			mode = ModeStartTLS
		}
	}
	return Config{
		Host:        getOr("SMTP_HOST", "localhost"),
		Port:        getIntOr("SMTP_PORT", 1025),
		User:        os.Getenv("SMTP_USER"),
		Pass:        os.Getenv("SMTP_PASS"),
		From:        getOr("SMTP_FROM", "no-reply@example.org"),
		TLSMode:     mode,
		TLSInsecure: getBoolOr("SMTP_TLS_INSECURE", false),
		CAPEM:       os.Getenv("SMTP_CA_PEM"),
	}
}

// Check refuses a configuration no message could go out with.
func (c Config) Check() error {
	switch c.TLSMode {
	case ModeNone, ModeStartTLS, ModeTLS:
	default:
		return fmt.Errorf("SMTP_TLS_MODE %q isn't %s, %s or %s", c.TLSMode, ModeNone, ModeStartTLS, ModeTLS)
	}
	if _, err := c.tlsConfig(); err != nil {
		return err
	}
	return nil
}

// Encrypted reports whether the connection is encrypted.
func (c Config) Encrypted() bool { return c.TLSMode == ModeStartTLS || c.TLSMode == ModeTLS }

func (c Config) tlsConfig() (*tls.Config, error) {
	// #nosec G402 -- InsecureSkipVerify is opt-in (SMTP_TLS_INSECURE) for a
	// relay whose cert is legacy-CN (no SANs); connection stays encrypted.
	// Defaults false (verified).
	cfg := &tls.Config{ServerName: c.Host, InsecureSkipVerify: c.TLSInsecure, MinVersion: tls.VersionTLS12} //nolint:gosec
	if strings.TrimSpace(c.CAPEM) == "" {
		return cfg, nil
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM([]byte(c.CAPEM)) {
		return nil, errors.New("SMTP_CA_PEM holds no PEM certificate")
	}
	cfg.RootCAs = pool
	return cfg, nil
}

// Sender sends plaintext emails. Implemented by Client; an interface so the
// OTP handlers can be unit-tested with a fake.
type Sender interface {
	Send(to, subject, body string) error
}

// Client is the net/smtp-backed Sender.
type Client struct {
	cfg Config
}

// New returns a Client for the given config.
func New(cfg Config) *Client { return &Client{cfg: cfg} }

// Send delivers a plaintext message to a single recipient: it connects in the
// configured TLS mode, authenticates when SMTP_USER is set, and sends.
func (c *Client) Send(to, subject, body string) error {
	client, err := c.open()
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	msg := buildMessage(c.cfg.From, to, subject, body)
	if err := client.Mail(c.cfg.From); err != nil {
		return fmt.Errorf("smtp mail from: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("smtp rcpt to: %w", err)
	}
	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := wc.Write(msg); err != nil {
		_ = wc.Close()
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("smtp close data: %w", err)
	}
	return client.Quit()
}

// open connects in the configured TLS mode and authenticates; nothing of the
// message has gone out yet.
func (c *Client) open() (*smtp.Client, error) {
	if err := c.cfg.Check(); err != nil {
		return nil, fmt.Errorf("smtp config: %w", err)
	}
	tlsCfg, _ := c.cfg.tlsConfig()
	addr := net.JoinHostPort(c.cfg.Host, strconv.Itoa(c.cfg.Port))
	dialer := &net.Dialer{Timeout: timeout}
	var conn net.Conn
	var err error
	if c.cfg.TLSMode == ModeTLS {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("smtp dial: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	client, err := smtp.NewClient(conn, c.cfg.Host)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("smtp greeting: %w", err)
	}
	if err := c.secure(client, tlsCfg); err != nil {
		_ = client.Close()
		return nil, err
	}
	return client, nil
}

// secure upgrades the connection with STARTTLS when the mode says so, then
// authenticates when SMTP_USER is set.
func (c *Client) secure(client *smtp.Client, tlsCfg *tls.Config) error {
	if c.cfg.TLSMode == ModeStartTLS {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return errors.New("smtp starttls: the relay doesn't offer STARTTLS; nothing was sent")
		}
		if err := client.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("smtp starttls: %w", err)
		}
	}
	if c.cfg.User == "" {
		return nil
	}
	ok, mechs := client.Extension("AUTH")
	if !ok {
		return errors.New("smtp auth: the relay offers no AUTH, and SMTP_USER is set")
	}
	auth := &relayAuth{user: c.cfg.User, pass: c.cfg.Pass, login: !slices.Contains(strings.Fields(strings.ToUpper(mechs)), "PLAIN")}
	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("smtp auth: %w", err)
	}
	return nil
}

// relayAuth is AUTH PLAIN, or LOGIN for a relay that offers only that. Unlike
// smtp.PlainAuth it also sends over a connection that isn't encrypted: with
// SMTP_TLS_MODE=none the operator chose that.
type relayAuth struct {
	user, pass string
	login      bool
	step       int
}

func (a *relayAuth) Start(*smtp.ServerInfo) (string, []byte, error) {
	if a.login {
		return "LOGIN", nil, nil
	}
	return "PLAIN", []byte("\x00" + a.user + "\x00" + a.pass), nil
}

func (a *relayAuth) Next(_ []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	if !a.login {
		return nil, errors.New("unexpected server challenge")
	}
	a.step++
	switch a.step {
	case 1:
		return []byte(a.user), nil
	case 2:
		return []byte(a.pass), nil
	}
	return nil, errors.New("unexpected server challenge")
}

// buildMessage assembles RFC 5322 headers + body as a CRLF byte slice.
func buildMessage(from, to, subject, body string) []byte {
	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + to + "\r\n")
	b.WriteString("Subject: " + subject + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=\"utf-8\"\r\n")
	b.WriteString("\r\n")
	b.WriteString(strings.ReplaceAll(body, "\n", "\r\n"))
	b.WriteString("\r\n")
	return []byte(b.String())
}

func getOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func getIntOr(k string, d int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return d
}

func getBoolOr(k string, d bool) bool {
	if v := os.Getenv(k); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return d
}
