# Export classification

This repository uses only standard, publicly documented cryptographic algorithms and protocols:
TOTP (RFC 6238) via pquerna/otp for second-factor enrollment and verification; WebAuthn/FIDO2
passkey registration and assertion verification (ECDSA, RSA and Ed25519 signatures per the
WebAuthn spec) via go-webauthn; AES-256-GCM to encrypt stored secrets; TLS and X.509 certificate
verification for SMTP STARTTLS when sending email one-time-passcodes; SHA-256 and crypto/rand for
one-time-passcode hashing and digit generation; and RS256/ES256 JWT verification of Kubernetes
projected ServiceAccount tokens (go-workload-identity) for service-to-service calls. None of it is
non-standard or proprietary cryptography.

This repository's source code is public, so under the US Export Administration Regulations (15
CFR 742.15(b)) it is not subject to the EAR: no classification, licence or notification applies to
it. Builds and binaries produced from this public source carry the same treatment under 15 CFR
734.3(b)(3) and 734.17.

This file is a factual statement about the cryptography used in Sneakers-PAM, not legal advice.
