// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"strings"
	"sync"

	postgres "github.com/Bugs5382/go-postgres"
	"google.golang.org/grpc/metadata"
)

// HeaderDependencyPrefix starts the health check header that carries a
// dependency's version: sneakers-dep-postgres, sneakers-dep-rabbitmq.
const HeaderDependencyPrefix = "sneakers-dep-"

const maxDependencyVersion = 64

var dependencies sync.Map // name -> version

// SetDependencyVersion records the version of a dependency (postgres) for the
// health check headers. Only the first token is kept ("16.4" from
// "16.4 (Debian ...)"), capped at 64 characters; an empty value removes it.
func SetDependencyVersion(name, raw string) {
	v := ""
	if f := strings.Fields(raw); len(f) > 0 {
		v = f[0]
	}
	if len(v) > maxDependencyVersion {
		v = v[:maxDependencyVersion]
	}
	if v == "" {
		dependencies.Delete(name)
		return
	}
	dependencies.Store(name, v)
}

// RecordPostgresVersion reads the database server's version once and records
// it as the postgres dependency. On error nothing is recorded; the caller logs
// it and carries on.
func RecordPostgresVersion(ctx context.Context, q postgres.Querier) error {
	var v string
	if err := q.QueryRow(ctx, "SHOW server_version").Scan(&v); err != nil {
		return err
	}
	SetDependencyVersion("postgres", v)
	return nil
}

func addDependencyHeaders(md metadata.MD) {
	dependencies.Range(func(k, v any) bool {
		md.Set(HeaderDependencyPrefix+k.(string), v.(string))
		return true
	})
}
