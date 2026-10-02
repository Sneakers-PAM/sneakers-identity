// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package email is a tiny env-driven SMTP sender used by the OTP flows (the MFA
// email second factor, password reset and email verification). In dev it
// targets the maildev catcher (maildev:1025, no auth, no TLS); in prod SMTP_*
// point at a real relay.
//
// The sender is deliberately minimal: plaintext messages over net/smtp, with
// AUTH only when SMTP_USER is set and STARTTLS only when SMTP_TLS is true. This
// matches the maildev default (no auth, plaintext) so a fresh dev box works
// with zero config.
package email

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"strconv"
	"strings"
)

// Config is the resolved SMTP configuration. Build it with LoadConfig, which
// reads SMTP_* from the environment with maildev-friendly defaults.
type Config struct {
	Host string // SMTP_HOST (default "localhost")
	Port int    // SMTP_PORT (default 1025)
	User string // SMTP_USER (default "" — maildev needs no auth)
	Pass string // SMTP_PASS (default "")
	From string // SMTP_FROM (default "no-reply@example.org")
	TLS  bool   // SMTP_TLS (default false for maildev)
	// TLSInsecure skips STARTTLS certificate verification (SMTP_TLS_INSECURE,
	// default false). For a relay whose cert uses a legacy CN with no SANs
	// (Go 1.15+ rejects it): the connection is still encrypted, just not
	// cert-verified. Only set true for a trusted internal relay.
	TLSInsecure bool
}

// LoadConfig reads SMTP_* env vars with dev (maildev) defaults.
func LoadConfig() Config {
	return Config{
		Host:        getOr("SMTP_HOST", "localhost"),
		Port:        getIntOr("SMTP_PORT", 1025),
		User:        os.Getenv("SMTP_USER"),
		Pass:        os.Getenv("SMTP_PASS"),
		From:        getOr("SMTP_FROM", "no-reply@example.org"),
		TLS:         getBoolOr("SMTP_TLS", false),
		TLSInsecure: getBoolOr("SMTP_TLS_INSECURE", false),
	}
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

// Send delivers a plaintext message to a single recipient. When SMTP_USER is
// empty and SMTP_TLS is false (the maildev case) it does a bare SMTP handshake
// with no auth; otherwise it STARTTLS-upgrades and authenticates.
func (c *Client) Send(to, subject, body string) error {
	addr := net.JoinHostPort(c.cfg.Host, strconv.Itoa(c.cfg.Port))
	msg := buildMessage(c.cfg.From, to, subject, body)

	if !c.cfg.TLS && c.cfg.User == "" {
		// Plaintext, no-auth path (maildev): use SendMail with a nil auth.
		return smtp.SendMail(addr, nil, c.cfg.From, []string{to}, msg)
	}

	// Authenticated / TLS path for a real relay.
	client, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("smtp dial: %w", err)
	}
	defer func() { _ = client.Close() }()

	if c.cfg.TLS {
		// #nosec G402 -- InsecureSkipVerify is opt-in (SMTP_TLS_INSECURE) for a
		// relay whose cert is legacy-CN (no SANs); connection stays
		// encrypted. Defaults false (verified).
		tlsCfg := &tls.Config{ServerName: c.cfg.Host, InsecureSkipVerify: c.cfg.TLSInsecure} //nolint:gosec
		if err := client.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("smtp starttls: %w", err)
		}
	}
	if c.cfg.User != "" {
		auth := smtp.PlainAuth("", c.cfg.User, c.cfg.Pass, c.cfg.Host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
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
