#!/usr/bin/env bash
# Checks that internal/workloadauth/ is a byte-for-byte copy of the canonical
# package in sneakers-vault at SNEAKERS_VAULT_REF (proto-refs.env), tests
# included.
#
# SNEAKERS_VAULT_DIR points at a local sneakers-vault checkout instead, for
# trying an unmerged change.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
source "$root/proto-refs.env"

canonical="$(mktemp -d)"
trap 'rm -rf "$canonical"' EXIT

if [[ -n "${SNEAKERS_VAULT_DIR:-}" ]]; then
  echo "workloadauth: sneakers-vault from $SNEAKERS_VAULT_DIR"
  cp -R "$SNEAKERS_VAULT_DIR/internal/workloadauth/." "$canonical/"
else
  echo "workloadauth: sneakers-vault at $SNEAKERS_VAULT_REF"
  curl -sSfL "https://codeload.github.com/Sneakers-PAM/sneakers-vault/tar.gz/$SNEAKERS_VAULT_REF" |
    tar -xz -C "$canonical" --strip-components=3 --wildcards '*/internal/workloadauth/*'
fi

if ! diff -r "$canonical" "$root/internal/workloadauth"; then
  echo "internal/workloadauth differs from sneakers-vault at $SNEAKERS_VAULT_REF." >&2
  echo "Copy the package from there unchanged, or bump SNEAKERS_VAULT_REF with a fresh copy." >&2
  exit 1
fi
echo "workloadauth: identical to sneakers-vault"
