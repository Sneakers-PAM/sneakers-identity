// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package kratos

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"
)

// Runs against a real Kratos (test/kratos has a config for v1.3.1) when
// KRATOS_TEST_ADMIN_URL and KRATOS_TEST_PUBLIC_URL are set.
func realKratos(t *testing.T) (*Admin, string) {
	t.Helper()
	admin, public := os.Getenv("KRATOS_TEST_ADMIN_URL"), os.Getenv("KRATOS_TEST_PUBLIC_URL")
	if admin == "" || public == "" {
		t.Skip("set KRATOS_TEST_ADMIN_URL and KRATOS_TEST_PUBLIC_URL to run against a real Kratos")
	}
	return NewAdmin(admin), public
}

// passwordLogin runs the self-service API login flow, as the gateway does.
func passwordLogin(t *testing.T, public, identifier, password string) bool {
	t.Helper()
	res, err := http.Get(public + "/self-service/login/api")
	if err != nil {
		t.Fatal(err)
	}
	var flow struct{ ID string }
	_ = json.NewDecoder(res.Body).Decode(&flow)
	_ = res.Body.Close()
	body, _ := json.Marshal(map[string]string{"method": "password", "identifier": identifier, "password": password})
	res, err = http.Post(public+"/self-service/login?flow="+flow.ID, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	return res.StatusCode == http.StatusOK
}

func TestRealKratosAdminSetPasswordEnablesLogin(t *testing.T) {
	a, public := realKratos(t)
	ctx := context.Background()
	email := fmt.Sprintf("cutover-%d@example.org", time.Now().UnixNano())

	id, err := a.CreateIdentity(ctx, email, "Cut Over")
	if err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}
	t.Cleanup(func() { _ = a.DeleteIdentity(context.Background(), id) })
	if passwordLogin(t, public, email, "no-password-yet-123") {
		t.Fatal("an identity created without credentials must not be able to log in")
	}

	if err := a.SetPassword(ctx, id, "a-new-long-password-9"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if !passwordLogin(t, public, email, "a-new-long-password-9") {
		t.Fatal("login with the admin-set password must succeed")
	}
	if passwordLogin(t, public, email, "the-wrong-password-9") {
		t.Fatal("login with a wrong password must fail")
	}
	if found, err := a.FindIdentityByEmail(ctx, email); err != nil || found != id {
		t.Fatalf("FindIdentityByEmail = %q, %v; want %q", found, err, id)
	}
}
