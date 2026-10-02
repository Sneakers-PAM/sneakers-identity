// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	c, err := NewFromString(strings.Repeat("a", 64)) // 32 bytes as hex
	if err != nil {
		t.Fatalf("NewFromString: %v", err)
	}
	const plain = "JBSWY3DPEHPK3PXP"
	sealed, err := c.Seal(plain)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if sealed == plain || strings.Contains(sealed, plain) {
		t.Fatal("sealed value must not expose the plaintext")
	}
	// A fresh nonce per call → the same plaintext seals to different ciphertexts.
	sealed2, _ := c.Seal(plain)
	if sealed == sealed2 {
		t.Fatal("expected a fresh nonce per Seal")
	}
	got, err := c.Open(sealed)
	if err != nil || got != plain {
		t.Fatalf("Open round-trip: got %q err %v", got, err)
	}
}

func TestOpenWrongKeyFails(t *testing.T) {
	c1, _ := NewFromString(hex.EncodeToString(make([]byte, 32)))
	c2, _ := NewFromString(strings.Repeat("b", 64))
	sealed, _ := c1.Seal("secret")
	if _, err := c2.Open(sealed); err == nil {
		t.Fatal("Open with the wrong key must fail (authentication)")
	}
}

func TestOpenTamperFails(t *testing.T) {
	c, _ := NewFromString(strings.Repeat("c", 64))
	sealed, _ := c.Seal("secret")
	raw, _ := base64.StdEncoding.DecodeString(sealed)
	raw[len(raw)-1] ^= 0xff // flip a ciphertext bit
	if _, err := c.Open(base64.StdEncoding.EncodeToString(raw)); err == nil {
		t.Fatal("Open of tampered ciphertext must fail")
	}
}

func TestNewFromStringRejectsBadKeys(t *testing.T) {
	cases := []string{"", "short", strings.Repeat("a", 63), base64.StdEncoding.EncodeToString(make([]byte, 16))}
	for _, s := range cases {
		if _, err := NewFromString(s); err == nil {
			t.Fatalf("expected rejection for key %q", s)
		}
	}
	// Accepts both hex (64 chars) and std-base64 of 32 bytes.
	if _, err := NewFromString(base64.StdEncoding.EncodeToString(make([]byte, 32))); err != nil {
		t.Fatalf("base64 32-byte key should be accepted: %v", err)
	}
}
