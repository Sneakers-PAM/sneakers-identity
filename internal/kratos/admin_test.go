// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package kratos

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeAdmin is an in-memory stand-in for the Kratos admin API endpoints the
// client uses.
type fakeAdmin struct {
	mu         sync.Mutex
	identities map[string]map[string]any
	passwords  map[string]string
	nextID     int
}

func newFakeAdmin(t *testing.T) (*fakeAdmin, *Admin) {
	t.Helper()
	f := &fakeAdmin{identities: map[string]map[string]any{}, passwords: map[string]string{}}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	return f, NewAdmin(srv.URL)
}

func (f *fakeAdmin) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	id := strings.TrimPrefix(r.URL.Path, "/admin/identities/")
	switch {
	case r.URL.Path == "/admin/identities" && r.Method == http.MethodGet:
		f.list(w, r.URL.Query().Get("credentials_identifier"))
	case r.URL.Path == "/admin/identities" && r.Method == http.MethodPost:
		f.create(w, body)
	case id == r.URL.Path:
		w.WriteHeader(http.StatusNotImplemented)
	case r.Method == http.MethodGet:
		f.get(w, id)
	case r.Method == http.MethodPut:
		f.put(w, id, body)
	case r.Method == http.MethodDelete:
		delete(f.identities, id)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotImplemented)
	}
}

func (f *fakeAdmin) list(w http.ResponseWriter, email string) {
	out := []map[string]any{}
	for id, traits := range f.identities {
		if strings.EqualFold(traits["email"].(string), email) {
			out = append(out, map[string]any{"id": id, "traits": traits})
		}
	}
	_ = json.NewEncoder(w).Encode(out)
}

func (f *fakeAdmin) create(w http.ResponseWriter, body []byte) {
	var in struct {
		Traits      map[string]any `json:"traits"`
		Credentials map[string]any `json:"credentials"`
	}
	_ = json.Unmarshal(body, &in)
	for _, tr := range f.identities {
		if strings.EqualFold(tr["email"].(string), in.Traits["email"].(string)) {
			w.WriteHeader(http.StatusConflict)
			return
		}
	}
	f.nextID++
	id := "kid-" + string(rune('0'+f.nextID))
	f.identities[id] = in.Traits
	if in.Credentials != nil {
		f.passwords[id] = "set"
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "traits": in.Traits})
}

func (f *fakeAdmin) get(w http.ResponseWriter, id string) {
	tr, ok := f.identities[id]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "schema_id": "default", "state": "active", "traits": tr})
}

func (f *fakeAdmin) put(w http.ResponseWriter, id string, body []byte) {
	if _, ok := f.identities[id]; !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	var in struct {
		Traits      map[string]any `json:"traits"`
		Credentials struct {
			Password struct {
				Config struct {
					Password string `json:"password"`
				} `json:"config"`
			} `json:"password"`
		} `json:"credentials"`
	}
	_ = json.Unmarshal(body, &in)
	f.identities[id] = in.Traits
	if p := in.Credentials.Password.Config.Password; p != "" {
		f.passwords[id] = p
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "traits": in.Traits})
}

func TestCreateIdentitySplitsTheNameIntoTraits(t *testing.T) {
	f, a := newFakeAdmin(t)
	id, err := a.CreateIdentity(context.Background(), "ada@example.org", "Ada King Lovelace")
	if err != nil || id == "" {
		t.Fatalf("CreateIdentity = %q, %v", id, err)
	}
	tr := f.identities[id]
	if tr["email"] != "ada@example.org" || tr["first_name"] != "Ada" || tr["last_name"] != "King Lovelace" {
		t.Fatalf("traits = %v", tr)
	}
	if _, has := f.passwords[id]; has {
		t.Fatal("CreateIdentity must not set a password")
	}
}

func TestFindIdentityByEmail(t *testing.T) {
	_, a := newFakeAdmin(t)
	ctx := context.Background()
	id, _ := a.CreateIdentity(ctx, "ada@example.org", "Ada")
	got, err := a.FindIdentityByEmail(ctx, "ADA@example.org")
	if err != nil || got != id {
		t.Fatalf("FindIdentityByEmail = %q, %v; want %q", got, err, id)
	}
	if _, err := a.FindIdentityByEmail(ctx, "nobody@example.org"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown email: want ErrNotFound, got %v", err)
	}
}

func TestSetPasswordKeepsTraits(t *testing.T) {
	f, a := newFakeAdmin(t)
	ctx := context.Background()
	id, _ := a.CreateIdentity(ctx, "ada@example.org", "Ada Lovelace")
	if err := a.SetPassword(ctx, id, "correct horse battery"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if f.passwords[id] != "correct horse battery" || f.identities[id]["email"] != "ada@example.org" {
		t.Fatalf("password = %q traits = %v", f.passwords[id], f.identities[id])
	}
}

func TestUpdateTraits(t *testing.T) {
	f, a := newFakeAdmin(t)
	ctx := context.Background()
	id, _ := a.CreateIdentity(ctx, "ada@example.org", "Ada Lovelace")
	if err := a.UpdateTraits(ctx, id, "ada.k@example.org", "Ada King"); err != nil {
		t.Fatalf("UpdateTraits: %v", err)
	}
	if tr := f.identities[id]; tr["email"] != "ada.k@example.org" || tr["last_name"] != "King" {
		t.Fatalf("traits = %v", tr)
	}
}

func TestDeleteIdentity(t *testing.T) {
	f, a := newFakeAdmin(t)
	ctx := context.Background()
	id, _ := a.CreateIdentity(ctx, "ada@example.org", "Ada")
	if err := a.DeleteIdentity(ctx, id); err != nil || len(f.identities) != 0 {
		t.Fatalf("DeleteIdentity = %v, identities = %v", err, f.identities)
	}
}

func TestCreateIdentityConflictIsReported(t *testing.T) {
	_, a := newFakeAdmin(t)
	ctx := context.Background()
	if _, err := a.CreateIdentity(ctx, "ada@example.org", "Ada"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.CreateIdentity(ctx, "ada@example.org", "Ada"); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate email: want ErrConflict, got %v", err)
	}
}
