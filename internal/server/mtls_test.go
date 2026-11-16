// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
	mtls "github.com/Bugs5382/go-mtls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// testProvider writes a throwaway CA and a localhost leaf and returns a
// provider over them.
func testProvider(t *testing.T) *mtls.Provider {
	t.Helper()
	dir := t.TempDir()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	w := func(name, typ string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: b}), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	p, err := mtls.NewProvider(mtls.Files{
		Cert: w("tls.crt", "CERTIFICATE", der),
		Key:  w("tls.key", "EC PRIVATE KEY", keyDER),
		CA:   w("ca.crt", "CERTIFICATE", caDER),
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func checkHealth(ctx context.Context, target string, opt grpc.DialOption) error {
	cc, err := grpc.NewClient(target, opt)
	if err != nil {
		return err
	}
	defer func() { _ = cc.Close() }()
	_, err = healthpb.NewHealthClient(cc).Check(ctx, &healthpb.HealthCheckRequest{})
	return err
}

// With mTLS on, the main port refuses a plaintext caller and answers a
// caller holding a certificate, while the health-only port answers plaintext
// (the kubelet probe cannot present a certificate).
func TestRunWithHealthPort_MTLSMainPlainHealth(t *testing.T) {
	p := testProvider(t)
	port, hport := freePort(t), freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- RunWithHealthPort(ctx, port, hport, log.Nop(), nil, func(*grpc.Server) {}, p.ServerOption())
	}()
	t.Cleanup(func() {
		cancel()
		waitDone(t, done)
	})

	call := func(target string, opt grpc.DialOption) error {
		c, stop := context.WithTimeout(ctx, 2*time.Second)
		defer stop()
		return checkHealth(c, target, opt)
	}
	waitFor(t, func() bool { return call("localhost:"+port, p.DialOption()) == nil })

	if err := call("localhost:"+port, grpc.WithTransportCredentials(insecure.NewCredentials())); err == nil {
		t.Fatal("main port answered a plaintext caller")
	}
	if err := call("127.0.0.1:"+hport, grpc.WithTransportCredentials(insecure.NewCredentials())); err != nil {
		t.Fatalf("health port refused plaintext: %v", err)
	}
}

// The health port serves health only: no other service is registered on it.
func TestRunWithHealthPort_HealthPortServesOnlyHealth(t *testing.T) {
	port, hport := freePort(t), freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- RunWithHealthPort(ctx, port, hport, log.Nop(), nil, func(s *grpc.Server) {
			s.RegisterService(&grpc.ServiceDesc{ServiceName: "t.Other", HandlerType: (*any)(nil)}, struct{}{})
		})
	}()
	t.Cleanup(func() { cancel(); waitDone(t, done) })
	waitFor(t, func() bool {
		c, stop := context.WithTimeout(ctx, time.Second)
		defer stop()
		return checkHealth(c, "127.0.0.1:"+hport, grpc.WithTransportCredentials(insecure.NewCredentials())) == nil
	})
	cc, err := grpc.NewClient("127.0.0.1:"+hport, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cc.Close() }()
	c, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()
	if err := cc.Invoke(c, "/t.Other/M", &healthpb.HealthCheckRequest{}, &healthpb.HealthCheckResponse{}); err == nil {
		t.Fatal("health port routed a non-health service")
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("condition not met in 5s")
}

// waitDone waits for a server goroutine to return and fails the test on its
// error or when it does not stop.
func waitDone(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("server returned: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("server did not stop in 5s")
	}
}
