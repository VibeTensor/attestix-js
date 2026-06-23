# Changelog

All notable changes to the `attestix` npm package are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.1] - 2026-06-16

### Fixed
- Canonicalize integers beyond 2^53 via BigInt. The canonicalizer previously
  accepted only `number`, so large integers lost precision before serialization
  and the JS verifier could reject a signature the Python/Go/Rust/Java/R ports
  accept. `JsonValue` now includes `bigint` (serialized as its exact decimal),
  and `parseCanonicalJson()` preserves out-of-safe-range integers as BigInt.
  The `canon-001` conformance test now asserts the true reference bytes.

### Docs
- Removed em/en-dashes from README/CHANGELOG/SPEC prose; synced stale Attestix
  core version references; added CODE_OF_CONDUCT.

### Notes
- The bare `attestix` package is now published on npm (0.4.1). The scoped
  `@vibetensor/attestix` is deprecated; prefer `attestix` in new code. This
  supersedes the 0.4.0 "Publishing is not yet done" note below.

## [0.4.0] - 2026-05-30

Version alignment to the Attestix 0.4.0 release line: the JS/TS engine now
shares its name and version with the Python `attestix` 0.4.0 stable release on
PyPI and the other verifier ports (Go, Rust, Java, R), so the story is "same
name, same version, same conformance suite, every ecosystem."

### Changed

- Bumped `0.2.0` → `0.4.0` to match the Attestix 0.4.0 release across all engines.
- `description` now states that the package verifies credentials and delegation
  chains issued by **Attestix 0.4.0** and conforms to the shared `spec/verify/v1`
  vectors.

### Added

- **Shared cross-language conformance vectors.** `tests/conformance.test.ts`
  loads the authoritative `vectors.json` from the foundation repo
  (`VibeTensor/attestix:spec/verify/v1`, attestix 0.4.0) and drives every kind
  through the public API (`canonicalize`, `didKeyToPublicKey`,
  `verifyCredential`, and `verifyDelegationChain`). This is the **same** suite the
  Go / Rust / Java / R ports must reproduce byte-for-byte, so the npm engine is
  now on the identical conformance contract. The vectors are vendored at
  `tests/vectors/conformance/vectors.json`.
  - Note: the `canon-001` vector includes `9007199254740993` (2^53 + 1), which a
    JS `number` cannot represent exactly; the test accounts for that known
    runtime limitation and still asserts the rest byte-for-byte.

### Notes

- This release was staged for publish via GitHub Release (OIDC trusted
  publishing, `.github/workflows/publish.yml`). Superseded by 0.4.1: the bare
  `attestix` name is now published on npm and the scoped `@vibetensor/attestix`
  is deprecated.

## [0.2.0]

### Added

- Offline, cross-engine verification of Attestix Ed25519-signed W3C Verifiable
  Credentials / Presentations and UCAN-style delegation chains (`verifyCredential`,
  `verifyPresentation`, `verifyDelegationChain`) plus the lower-level
  `canonicalize`, `did:key` codec, and raw `verifyEd25519` primitives. No network
  access; one small audited dependency (`@noble/curves`). Tracks the cross-engine
  interop work in [attestix#7](https://github.com/VibeTensor/attestix/issues/7).
- Claimed the bare `attestix` name on npm (renamed from `@vibetensor/attestix`).

## [0.1.0]

### Added

- Initial REST client (`AttestixClient`) for the Attestix API: identity,
  credentials, compliance, reputation, provenance, delegation, DID, and
  blockchain anchoring, with typed errors and automatic retry/backoff.
