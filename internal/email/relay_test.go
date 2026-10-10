// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package email

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// relay is a small SMTP server for the tests: plain, STARTTLS or implicit
// TLS, with AUTH PLAIN and LOGIN, recording what each session did.
type relay struct {
	t        *testing.T
	ln       net.Listener
	cert     tls.Certificate
	caPEM    string
	implicit bool
	starttls bool
	auth     []string
	user     string
	pass     string

	mu   sync.Mutex
	got  []session
	done chan struct{}
}

type session struct {
	tls      bool
	authUser string
	authMech string
	from     string
	rcpt     string
	data     string
}

// newRelay starts a relay whose certificate names 127.0.0.1 and is signed
// by its own CA (caPEM).
func newRelay(t *testing.T, implicit, starttls bool, auth ...string) *relay {
	t.Helper()
	r := &relay{t: t, implicit: implicit, starttls: starttls, auth: auth, user: "relay-user", pass: "relay-pass", done: make(chan struct{})}
	r.cert, r.caPEM = testCert(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if implicit {
		ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{r.cert}, MinVersion: tls.VersionTLS12})
	}
	r.ln = ln
	go r.serve()
	t.Cleanup(func() { _ = ln.Close(); <-r.done })
	return r
}

func (r *relay) port() int { return r.ln.Addr().(*net.TCPAddr).Port }

// sessions are the sessions so far, waiting a moment for one to end: the
// client may hang up before the relay has noted it.
func (r *relay) sessions() []session {
	for i := 0; i < 200; i++ {
		r.mu.Lock()
		n := len(r.got)
		r.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]session(nil), r.got...)
}

func (r *relay) serve() {
	defer close(r.done)
	for {
		c, err := r.ln.Accept()
		if err != nil {
			return
		}
		r.handle(c)
	}
}

func (r *relay) handle(c net.Conn) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	s := session{tls: r.implicit}
	defer func() {
		r.mu.Lock()
		r.got = append(r.got, s)
		r.mu.Unlock()
	}()
	rd, w := bufio.NewReader(c), c
	say := func(l string) { _, _ = w.Write([]byte(l + "\r\n")) }
	line := func() (string, bool) {
		l, err := rd.ReadString('\n')
		return strings.TrimRight(l, "\r\n"), err == nil
	}
	say("220 relay.example.org ESMTP")
	for {
		l, ok := line()
		if !ok {
			return
		}
		verb := strings.ToUpper(strings.SplitN(l, " ", 2)[0])
		switch verb {
		case "EHLO", "HELO":
			lines := []string{"relay.example.org"}
			if r.starttls && !s.tls {
				lines = append(lines, "STARTTLS")
			}
			if len(r.auth) > 0 {
				lines = append(lines, "AUTH "+strings.Join(r.auth, " "))
			}
			for i, x := range lines {
				sep := "-"
				if i == len(lines)-1 {
					sep = " "
				}
				say("250" + sep + x)
			}
		case "STARTTLS":
			say("220 go ahead")
			tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{r.cert}, MinVersion: tls.VersionTLS12})
			if err := tc.Handshake(); err != nil {
				return
			}
			c, rd, w = tc, bufio.NewReader(tc), tc
			s.tls = true
		case "AUTH":
			parts := strings.Fields(l)
			if len(parts) < 2 {
				say("501 syntax")
				continue
			}
			var user, pass string
			switch strings.ToUpper(parts[1]) {
			case "PLAIN":
				resp := ""
				if len(parts) > 2 {
					resp = parts[2]
				} else {
					say("334 ")
					resp, _ = line()
				}
				b, _ := base64.StdEncoding.DecodeString(resp)
				f := strings.Split(string(b), "\x00")
				if len(f) == 3 {
					user, pass = f[1], f[2]
				}
				s.authMech = "PLAIN"
			case "LOGIN":
				say("334 " + base64.StdEncoding.EncodeToString([]byte("Username:")))
				u, _ := line()
				say("334 " + base64.StdEncoding.EncodeToString([]byte("Password:")))
				p, _ := line()
				ub, _ := base64.StdEncoding.DecodeString(u)
				pb, _ := base64.StdEncoding.DecodeString(p)
				user, pass = string(ub), string(pb)
				s.authMech = "LOGIN"
			}
			if user == r.user && pass == r.pass {
				s.authUser = user
				say("235 ok")
			} else {
				say("535 bad credentials")
			}
		case "MAIL":
			s.from = strings.TrimSuffix(strings.TrimPrefix(l[len("MAIL FROM:"):], "<"), ">")
			say("250 ok")
		case "RCPT":
			s.rcpt = strings.TrimSuffix(strings.TrimPrefix(l[len("RCPT TO:"):], "<"), ">")
			say("250 ok")
		case "DATA":
			say("354 go")
			var b strings.Builder
			for {
				d, ok := line()
				if !ok || d == "." {
					break
				}
				b.WriteString(d + "\n")
			}
			s.data = b.String()
			say("250 queued")
		case "QUIT":
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}

func testCert(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "relay test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "127.0.0.1"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
}
