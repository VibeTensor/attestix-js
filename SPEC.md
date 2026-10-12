# Attestix JavaScript verification contract

This document describes the offline implementation currently present in main.
The [shared v1 vectors](tests/vectors/conformance/vectors.json) are the
compatibility reference, not a claim of support for every JSON value or policy.

## Ed25519 and did:key

The verifier uses @noble/curves Ed25519 with 32-byte public keys and 64-byte
signatures. A key identifier is `did:key:z` followed by base58btc of the
multicodec bytes `0xed 0x01` and the raw public key. The verifier rejects invalid
key encodings. It does not fetch a DID document or perform arbitrary DID-method
resolution.

## Canonical JSON

The signing form is JCS-style, not strict RFC 8785:

- NFC-normalize string values and object keys.
- Reject distinct object keys that collide after normalization.
- Sort normalized keys by Unicode code point, recursively.
- Use compact JSON separators and UTF-8 output. Escape quotes, backslashes,
  and control characters; non-ASCII text is emitted as UTF-8.
- Emit safe integer `number` values and exact `bigint` values as decimal
  integers. Whole-valued safe floats serialize as integers.
- Reject unsafe integer `number` values, signed zero, non-finite numbers, and
  floats whose JavaScript representation requires exponent notation.

Other finite non-integer decimal values are accepted, but general Python
float-format equivalence is not established. Prefer integer/string fields
for signed data. The vectors cover the simple decimal `1.5`.

`canonicalize(value)` returns UTF-8 bytes; `canonicalizeToString(value)` returns
the same serialization as a string. Unsupported values throw
`JcsUnsupportedValueError`. Do not treat canonicalization errors as success.

Precision must be preserved before canonicalization. Ordinary `JSON.parse`
can already round integer tokens beyond Number.MAX_SAFE_INTEGER. The internal
`parseCanonicalJson` helper in [src/verify/jcs.ts](src/verify/jcs.ts) uses parser
source context to preserve such tokens as bigint when the runtime provides it;
without that context it rejects them. It is not exported from the package root.
For public API use, supply a precision-preserving parsed value containing bigint;
do not silently round oversized JSON integer tokens.

Collision rejection applies to keys retained in the parsed object. It does not
promise rejection of identical duplicate raw JSON names before parsing.

## Credential proofs

The signed payload excludes only top-level `proof` and `credentialStatus`.
The key comes from signed `issuer` (string) or `issuer.id`. If
`proof.verificationMethod` is present, it must be a nonempty string and its
DID before `#` must equal that issuer. Unsigned proof metadata cannot substitute
a different key. Ed25519 verifies `proof.proofValue` over the canonical bytes.

The decoder accepts padded/unpadded base64url and both standard/url-safe
alphabets; Attestix VC wire proofs use padded base64url.

`verifyCredential` returns structured checks and `valid`. The verdict requires
structure, signature, expiry, and embedded status. Structure requires a type
array containing VerifiableCredential; this is not complete schema validation.

Absent expirationDate passes expiry. A present malformed date fails it. A valid
expiry requires `now < expiry`, with `now` in milliseconds since epoch;
non-finite `now` fails when checking a present expiry. `checkExpiry: false`
intentionally disables this check. A local revoked boolean fails status; absent
status does not establish current revocation state. There is no live status lookup.

## Presentation proofs

The signed VP excludes only top-level `proof`; its key comes from signed
`holder`, and present method metadata must identify that holder. Every embedded
credential is verified with the credential options. The result requires the
holder signature and all included credential results.

Challenge/domain expectations, freshness, and replay policy are application
checks; this function does not validate them. An empty embedded-credential list
is not independently rejected when the holder proof is valid.

## Delegation tokens

A token is compact JWS `base64url(header).base64url(payload).base64url(signature)`.
Signatures cover the literal first two segments joined by a dot, not canonical
JSON. Only EdDSA is accepted, using the token's `iss` did:key.

A single leaf token invokes recursive `prf` verification: signature checks,
numeric exp/nbf checks, repeated-jti detection, and child capability subset
against each referenced parent. An array is ordered leaf..root and checks each
listed signature/time plus consecutive capability subset; that array path does
not independently validate prf linkage or cycles.

Delegation time options are Unix seconds. Numeric exp is considered expired
when `exp + tolerance < now`; numeric nbf is not yet valid when
`nbf - tolerance > now`. Missing or non-numeric claims do not enforce a required
expiry. No iat, audience, or live-revocation policy is enforced. Apply required
claims and trust policy before authorization. `decodeDelegationUnsafe` only
decodes claims and is not a verification result.

## Compatibility evidence

[conformance.test.ts](tests/conformance.test.ts) exercises the vendored shared
vectors. [security-boundaries.test.ts](tests/security-boundaries.test.ts) and
[readiness-boundaries.test.ts](tests/readiness-boundaries.test.ts) cover issuer,
holder, malformed metadata/expiry, NFC collisions, and unsafe numeric inputs.
These describe tested cases and do not announce a new published package version.
