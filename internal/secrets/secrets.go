// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package secrets provides at-rest encryption for small credential blobs
// (currently the TOTP shared secret). It wraps AES-256-GCM: Seal produces
// base64(nonce || ciphertext) with a fresh random nonce per call, Open
// authenticates + decrypts. The key comes from the service environment
// (TOTP_ENC_KEY, 32 bytes as hex or std-base64) — identity has no KMS yet, so
// the env-provided key IS the at-rest key mechanism for this service.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// Cipher seals/opens small secrets with AES-256-GCM.
type Cipher struct {
	aead cipher.AEAD
}

// New returns a Cipher for a raw 32-byte key.
func New(key []byte) (*Cipher, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	return &Cipher{aead: aead}, nil
}

// NewFromString parses an env-shaped key — 64 hex chars or std-base64 of 32
// bytes — and returns a Cipher. Anything that doesn't decode to exactly 32
// bytes is rejected.
func NewFromString(s string) (*Cipher, error) {
	if s == "" {
		return nil, errors.New("encryption key is empty")
	}
	if raw, err := hex.DecodeString(s); err == nil && len(raw) == 32 {
		return New(raw)
	}
	if raw, err := base64.StdEncoding.DecodeString(s); err == nil && len(raw) == 32 {
		return New(raw)
	}
	return nil, errors.New("encryption key must decode (hex or base64) to 32 bytes")
}

// Seal encrypts plaintext and returns base64(nonce || ciphertext+tag).
func (c *Cipher) Seal(plaintext string) (string, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}
	out := c.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(out), nil
}

// Open decrypts a Seal output. Fails on wrong key, tampering, or malformed input.
func (c *Cipher) Open(sealed string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		return "", fmt.Errorf("decode: %w", err)
	}
	ns := c.aead.NonceSize()
	if len(raw) < ns {
		return "", errors.New("sealed value too short")
	}
	plain, err := c.aead.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}
	return string(plain), nil
}
