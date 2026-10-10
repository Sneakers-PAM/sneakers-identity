// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package email

import (
	"strings"
	"testing"
)

func cfgFor(r *relay, mode string) Config {
	return Config{Host: "127.0.0.1", Port: r.port(), From: "no-reply@sneakers.example.org", TLSMode: mode}
}

func sendOne(t *testing.T, c Config) error {
	t.Helper()
	return New(c).Send("someone@example.org", "Your code", "123456")
}

func onlySession(t *testing.T, r *relay) session {
	t.Helper()
	got := r.sessions()
	if len(got) != 1 {
		t.Fatalf("sessions = %d, want 1", len(got))
	}
	return got[0]
}

func TestSendsInEveryTLSMode(t *testing.T) {
	for _, c := range []struct {
		name               string
		mode               string
		implicit, starttls bool
		auth               []string
		user               bool
		ca, insecure       bool
		wantTLS            bool
		wantMech           string
	}{
		{name: "none, no auth", mode: ModeNone},
		{name: "none, authenticated", mode: ModeNone, auth: []string{"PLAIN", "LOGIN"}, user: true, wantMech: "PLAIN"},
		{name: "none, LOGIN only", mode: ModeNone, auth: []string{"LOGIN"}, user: true, wantMech: "LOGIN"},
		{name: "starttls, the relay's CA", mode: ModeStartTLS, starttls: true, auth: []string{"PLAIN"}, user: true, ca: true, wantTLS: true, wantMech: "PLAIN"},
		{name: "starttls, verify off", mode: ModeStartTLS, starttls: true, auth: []string{"LOGIN"}, user: true, insecure: true, wantTLS: true, wantMech: "LOGIN"},
		{name: "implicit tls, the relay's CA", mode: ModeTLS, implicit: true, auth: []string{"PLAIN"}, user: true, ca: true, wantTLS: true, wantMech: "PLAIN"},
		{name: "implicit tls, verify off", mode: ModeTLS, implicit: true, insecure: true, wantTLS: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newRelay(t, c.implicit, c.starttls, c.auth...)
			cfg := cfgFor(r, c.mode)
			if c.user {
				cfg.User, cfg.Pass = r.user, r.pass
			}
			if c.ca {
				cfg.CAPEM = r.caPEM
			}
			cfg.TLSInsecure = c.insecure
			if err := sendOne(t, cfg); err != nil {
				t.Fatalf("Send: %v", err)
			}
			s := onlySession(t, r)
			if s.tls != c.wantTLS || s.authMech != c.wantMech || s.from != cfg.From || s.rcpt != "someone@example.org" || !strings.Contains(s.data, "123456") {
				t.Fatalf("session = %+v", s)
			}
			if c.user && s.authUser != r.user {
				t.Fatalf("not authenticated: %+v", s)
			}
		})
	}
}

func TestRefusesWhatTheModeDoesNotAllow(t *testing.T) {
	t.Run("starttls without the relay offering it", func(t *testing.T) {
		r := newRelay(t, false, false, "PLAIN")
		cfg := cfgFor(r, ModeStartTLS)
		cfg.User, cfg.Pass = r.user, r.pass
		if err := sendOne(t, cfg); err == nil || !strings.Contains(err.Error(), "STARTTLS") {
			t.Fatalf("Send = %v, want a STARTTLS refusal", err)
		}
		if s := onlySession(t, r); s.authUser != "" || s.from != "" {
			t.Fatalf("credentials or mail went out in the clear: %+v", s)
		}
	})
	t.Run("an unknown CA with verify on", func(t *testing.T) {
		r := newRelay(t, false, true)
		if err := sendOne(t, cfgFor(r, ModeStartTLS)); err == nil || !strings.Contains(err.Error(), "certificate") {
			t.Fatalf("Send = %v, want a certificate error", err)
		}
	})
	t.Run("implicit tls with an unknown CA", func(t *testing.T) {
		r := newRelay(t, true, false)
		if err := sendOne(t, cfgFor(r, ModeTLS)); err == nil || !strings.Contains(err.Error(), "certificate") {
			t.Fatalf("Send = %v, want a certificate error", err)
		}
	})
	t.Run("a CA that isn't PEM", func(t *testing.T) {
		r := newRelay(t, false, true)
		cfg := cfgFor(r, ModeStartTLS)
		cfg.CAPEM = "not a certificate"
		if err := sendOne(t, cfg); err == nil || !strings.Contains(err.Error(), "SMTP_CA_PEM") {
			t.Fatalf("Send = %v, want a CA error", err)
		}
	})
	t.Run("credentials the relay doesn't take", func(t *testing.T) {
		r := newRelay(t, false, false, "PLAIN")
		cfg := cfgFor(r, ModeNone)
		cfg.User, cfg.Pass = r.user, "wrong"
		if err := sendOne(t, cfg); err == nil || !strings.Contains(err.Error(), "auth") {
			t.Fatalf("Send = %v, want an auth error", err)
		}
	})
	t.Run("a relay with no AUTH", func(t *testing.T) {
		r := newRelay(t, false, false)
		cfg := cfgFor(r, ModeNone)
		cfg.User, cfg.Pass = r.user, r.pass
		if err := sendOne(t, cfg); err == nil || !strings.Contains(err.Error(), "AUTH") {
			t.Fatalf("Send = %v, want a no-AUTH error", err)
		}
	})
}

func TestLoadConfigReadsTheTLSMode(t *testing.T) {
	for _, c := range []struct {
		mode, legacy, want string
	}{
		{"", "", ModeNone},
		{"", "true", ModeStartTLS},
		{"", "false", ModeNone},
		{"tls", "", ModeTLS},
		{"STARTTLS", "", ModeStartTLS},
		{"none", "true", ModeNone},
	} {
		t.Setenv("SMTP_TLS_MODE", c.mode)
		t.Setenv("SMTP_TLS", c.legacy)
		if got := LoadConfig().TLSMode; got != c.want {
			t.Errorf("SMTP_TLS_MODE=%q SMTP_TLS=%q: mode %q, want %q", c.mode, c.legacy, got, c.want)
		}
	}
	t.Setenv("SMTP_CA_PEM", "-----BEGIN CERTIFICATE-----")
	if LoadConfig().CAPEM == "" {
		t.Error("SMTP_CA_PEM isn't read")
	}
}

func TestCheckRefusesAnUnknownMode(t *testing.T) {
	if err := (Config{Host: "relay.example.org", Port: 587, TLSMode: "ssl"}).Check(); err == nil || !strings.Contains(err.Error(), "SMTP_TLS_MODE") {
		t.Fatalf("Check = %v", err)
	}
	for _, m := range []string{ModeNone, ModeStartTLS, ModeTLS} {
		if err := (Config{Host: "relay.example.org", Port: 587, TLSMode: m}).Check(); err != nil {
			t.Fatalf("Check(%s) = %v", m, err)
		}
	}
}
