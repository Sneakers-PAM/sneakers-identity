// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"sync"
	"testing"

	workloadauth "github.com/Bugs5382/go-workload-identity"
)

// fakeReadinessVerifier is a fake behind the ReadinessVerifier interface, not
// a mock of go-workload-identity's own Verifier.
// Its answer can change while the background refresh reads it.
type fakeReadinessVerifier struct {
	mu  sync.Mutex
	err error
}

func (f *fakeReadinessVerifier) set(err error) { f.mu.Lock(); f.err = err; f.mu.Unlock() }

func (f *fakeReadinessVerifier) Ready() error { f.mu.Lock(); defer f.mu.Unlock(); return f.err }

func TestWorkloadIdentity_NotReadyUntilKeySetLoads(t *testing.T) {
	dep := WorkloadIdentity(&fakeReadinessVerifier{err: workloadauth.ErrUnavailable})
	if dep.Name != "workload-identity" || !dep.Required {
		t.Fatalf("dep = %+v, want a required dependency named workload-identity", dep)
	}
	if err := dep.Check(context.Background()); !errors.Is(err, workloadauth.ErrUnavailable) {
		t.Fatalf("check = %v, want ErrUnavailable", err)
	}
}

func TestWorkloadIdentity_ReadyOnceKeySetLoads(t *testing.T) {
	dep := WorkloadIdentity(&fakeReadinessVerifier{})
	if err := dep.Check(context.Background()); err != nil {
		t.Fatalf("check = %v, want nil", err)
	}
}
