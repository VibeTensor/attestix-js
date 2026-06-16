# Attestix Cross-Engine Verification Spec

This document specifies the exact wire formats and canonicalization rules the
`attestix` offline verifier must reproduce to verify artifacts
produced by the Python Attestix engine (`VibeTensor/attestix`). It is the
authority for closing GitHub issue [VibeTensor/attestix#7](https://github.com/VibeTensor/attestix/issues/7)
(cross-engine interop). Everything here was derived by reading the Python
source and probing its actual byte output (not from a published standard), so
the JS side matches the **engine**, not an idealized RFC.

Source files inspected (in `D:\Development\vibetensor-products\Attestix`):

- `auth/crypto.py`: canonicalization, signing, did:key codec.
- `signing/inprocess_signer.py`, `signing/signer.py`: the signer seam (default = byte-identical to v0.4.0).
- `services/credential_service.py`: VC / VP issuance + proof.
- `services/delegation_service.py`: UCAN-style JWT delegation chains.
- `services/did_service.py`: did:key / did:web documents.
- `auth/token_parser.py`: JWT detection.

---

## 1. Ed25519

- Curve: Ed25519 (RFC 8032), via Python `cryptography` `Ed25519PrivateKey` / `Ed25519PublicKey`.
- Raw public key: 32 bytes. Raw private seed: 32 bytes.
- Signature: 64 bytes, standard Ed25519 (PureEdDSA).
- JS implementation uses `@noble/curves/ed25519` `ed25519.verify(sig, msg, pubkey)`.

## 2. did:key codec

`public_key_to_did_key` / `did_key_to_public_key` in `auth/crypto.py`:

```
did:key:z<base58btc(0xed01 || raw_pubkey_32_bytes)>
```

- Multicodec prefix for ed25519-pub: bytes `0xED 0x01` (`ED25519_MULTICODEC_PREFIX`).
- Multibase prefix: literal ASCII `z` (base58btc), placed **immediately after**
  `did:key:`. The base58btc alphabet is the Bitcoin alphabet
  (`123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`).
- Decode rejects anything whose first two decoded bytes are not `0xED 0x01`.
- Verification-method fragment (`did_key_fragment`): for `did:key:zXXXX`, the
  fragment is `#zXXXX` (the full multibase string, **including** the `z`). So a
  full verificationMethod id is `did:key:zXXXX#zXXXX`.

When verifying, the verifier extracts the issuer DID by splitting the proof's
`verificationMethod` on `#` and taking the part before it (matching Python's
`vm.split("#")[0]`). For credentials it falls back to `issuer.id`.

## 3. Canonical JSON (the critical interop surface)

`canonicalize_json(payload: dict) -> bytes` in `auth/crypto.py`. It is **NOT**
strict RFC 8785; it is `json.dumps` with specific options plus a pre-pass:

```python
normalized = _normalize_for_signing(payload)
canonical = json.dumps(normalized, sort_keys=True,
                       separators=(",", ":"), ensure_ascii=False)
return canonical.encode("utf-8")
```

Rules the JS canonicalizer (`src/verify/jcs.ts`) reproduces, verified
byte-for-byte against Python output:

1. **Object keys sorted by Unicode code point** (Python's default string sort).
   This is code-point order, *not* UTF-16 code-unit order. For the BMP these
   coincide; they only diverge for astral (> U+FFFF) keys, which do not occur
   in Attestix payloads. The JS sorter sorts by code point to match Python
   exactly regardless.
2. **Compact separators**: `,` between items, `:` between key and value. No
   spaces. (matches JS `JSON.stringify` default.)
3. **`ensure_ascii=False`**: non-ASCII characters are emitted as their raw UTF-8
   bytes, NOT `\uXXXX` escapes. e.g. `café` -> `caf\xc3\xa9`, `日本語` -> raw
   UTF-8. JS `JSON.stringify` already emits raw characters for printable
   non-ASCII, so the UTF-8 encoding of the resulting string matches.
4. **String escaping** matches JSON / JS `JSON.stringify` for the shared set:
   `"` -> `\"`, `\` -> `\\`, U+0008 -> `\b`, U+0009 -> `\t`, U+000A -> `\n`,
   U+000C -> `\f`, U+000D -> `\r`, and other control chars U+0000 to U+001F ->
   `\u00xx` (lowercase hex). `/` is NOT escaped. `<`, `>`, `&` are NOT escaped.
   U+007F (DEL) is emitted raw (not escaped) by both engines.
5. **NFC normalization** of every string (keys and values) via
   `unicodedata.normalize("NFC", s)`. JS reproduces with
   `String.prototype.normalize("NFC")`.
6. **Numbers**:
   - Integers serialize as integers (`1`, `100000000000`).
   - Whole-valued floats are coerced to integers before serialization
     (`1.0` -> `1`, `2.0` -> `2`) by `_normalize_for_signing`.
   - JS `JSON.stringify` already renders `1.0` as `1` and integer-valued
     numbers without a decimal point, so this matches for all integers and
     whole numbers that fit in a JS `number`.
7. **`null`, `true`, `false`** literal as in JSON.
8. Output is UTF-8 bytes.

### Known canonicalization divergences (documented, guarded, NOT silently wrong)

These differ between Python `json.dumps` and JS `JSON.stringify`. **None of
them occur in any Attestix signed payload** (which contain only strings,
integers, booleans, nulls, arrays, and nested objects). The JS canonicalizer
**detects and throws** on these inputs rather than emit a byte string that
would not match Python, so a verifier can never silently accept/reject due to a
canonicalization mismatch:

| Input | Python output | JS `JSON.stringify` | JS verifier behavior |
|---|---|---|---|
| `1e21` | `1000000000000000000000` | `1e+21` | throws `JcsUnsupportedValueError` |
| `1e-7` | `1e-07` | `1e-7` | throws `JcsUnsupportedValueError` |
| `-0.0` | `-0.0` | `0` | throws `JcsUnsupportedValueError` |
| `NaN` / `Infinity` | (Python emits `NaN`/`Infinity`, invalid JSON) | `null` | throws |
| non-integer float (e.g. `1.5`) | `1.5` | `1.5` | allowed (matches) for the common path; large/sci-notation guarded |

The verifier accepts finite integers (including those exactly representable),
non-integer finite floats whose JS string form has no exponent, booleans,
strings, null, arrays, and plain objects. Numbers requiring exponential
notation or signed-zero are rejected up front. Real Attestix VCs and JWT
delegation payloads never trip this guard.

## 4. JSON-payload signature (used by VCs and VPs)

`sign_json_payload(private_key, payload) -> str`:

```
proofValue = base64url( ed25519_sign( canonicalize_json(payload) ) )
```

- The signature is **base64url WITH padding** (Python `base64.urlsafe_b64encode`
  always emits `=` padding; a 64-byte signature encodes to 88 chars ending in
  `=`). The JS decoder accepts base64url with or without padding and with `+/`
  or `-_` alphabet, but the Python wire form is url-safe + padded.
- Verification recomputes `canonicalize_json(payload)` and checks the signature
  with the issuer's Ed25519 public key.

## 5. Verifiable Credential (W3C VC Data Model 1.1)

Issued by `CredentialService.issue_credential`. Structure:

```jsonc
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "urn:uuid:...",
  "type": ["VerifiableCredential", "<SpecificType>"],
  "issuer": { "id": "did:key:z...", "name": "..." },
  "issuanceDate": "ISO-8601",
  "expirationDate": "ISO-8601",
  "credentialSubject": { "id": "<subject>", ...claims },
  "credentialStatus": {                 // NOT signed (mutable)
    "id": "<id>#status",
    "type": "RevocationList2021Status",
    "revoked": false,
    "revocation_reason": null,
    "revoked_at": null
  },
  "proof": {                            // NOT signed (mutable)
    "type": "Ed25519Signature2020",
    "created": "ISO-8601",
    "verificationMethod": "did:key:z...#z...",
    "proofPurpose": "assertionMethod",
    "proofValue": "<base64url sig>"
  }
}
```

**Signed-field set (CRITICAL):** the signature covers the credential object with
the **`proof` and `credentialStatus` fields removed**
(`MUTABLE_FIELDS = {"proof", "credentialStatus"}`). i.e. the signed payload is:

```
{ @context, id, type, issuer, issuanceDate, expirationDate, credentialSubject }
```

canonicalized by the rules in §3. The verifier:

1. Strips `proof` and `credentialStatus`.
2. Canonicalizes the remainder.
3. Resolves issuer DID = `proof.verificationMethod` before `#`, else `issuer.id`.
4. Verifies `proof.proofValue` (base64url) over the canonical bytes with that
   did:key's public key.

It also checks structure (`type` contains `VerifiableCredential`), expiry
(`expirationDate` in the future), and (if present locally) revocation. The
offline JS verifier checks signature + structure + expiry; revocation is a
local-storage concern and is reported as "not checkable offline".

## 6. Verifiable Presentation (VP)

`create_verifiable_presentation`. Signed payload = the VP with **only `proof`
removed** (note: differs from VC, VP excludes `proof` only, not
`credentialStatus`). Each embedded credential is verified by §5 rules. The VP
`proof.proofPurpose` is `authentication`, and `challenge`/`domain` may be
present both at top level and inside `proof`.

## 7. UCAN-style delegation chain (JWT / EdDSA)

`DelegationService.create_delegation`. **This is a JWT, not a JSON-signature
object.** A delegation token is a compact JWS:

```
base64url(header) . base64url(payload) . base64url(signature)
```

- **Header**: `{"typ":"JWT","ucv":"0.9.0","alg":"EdDSA"}` (PyJWT serializes
  header keys; `alg` is `EdDSA`). The exact header bytes are whatever PyJWT
  emits; the verifier does NOT recanonicalize: it verifies over the literal
  `base64url(header) || "." || base64url(payload)` ASCII bytes, exactly as JWS
  requires.
- **Payload claims**:
  - `iss`: the **server** did:key (the signing identity for the whole chain).
  - `aud`, `sub`: the audience agent id (recipient).
  - `delegator`: the issuer agent id (logical granter).
  - `iat`, `nbf`, `exp`: unix seconds (integers).
  - `jti`: random url-safe id.
  - `att`: list of capability strings (the UCAN attenuation set).
  - `prf`: list of parent JWT strings (the proof chain). `[]` at the root.
  - `attestix_version`: `"0.1.0"`, `typ`: `"ucan/delegation"`.
- **Signature**: EdDSA (Ed25519) over the ASCII `signing input`
  (`b64url(header).b64url(payload)`), signed by the server key. Verified with
  the `iss` did:key's public key.

### Chain verification rules (`verifyDelegationChain`)

Reproduces `DelegationService.verify_delegation` recursion + the attenuation
check enforced at creation time in `create_delegation`:

1. **Each link's JWS signature** verifies against the public key derived from
   that link's `iss` did:key.
2. **Recursive `prf` verification**: every parent token in `prf` must itself be
   a valid link. Invalid ancestor => whole chain invalid.
3. **Cycle detection**: a `jti` seen twice in one verification run => reject
   ("Cycle detected").
4. **Capability attenuation**: a child's `att` set MUST be a subset of each of
   its parents' `att` sets. A capability present in the child but not the
   parent is privilege escalation => reject. (Python enforces this at creation;
   the offline verifier re-checks it across the supplied chain because an
   offline verifier cannot trust that creation-time checks ran.)
5. **Linkage**: the chain is rooted at the server `iss`; each link's `prf`
   entries are the parent tokens. The verifier walks root -> leaf.
6. **Expiry**: `exp` must be in the future (`exp >= now`); `nbf`/`iat` sanity.
   Expired link => reject (with `expired: true`).
7. **Revocation** is a local-storage concern (by `jti`) and is not checkable
   offline; reported as not-checked.

The JS verifier accepts either a single leaf JWT string (it walks `prf`
internally) or an explicit array of JWT strings root..leaf.

---

## 8. Summary of what JS must match byte-for-byte

| Concern | Rule |
|---|---|
| Canonical JSON | sort keys by code point, `,`/`:` separators, raw UTF-8 (no `\u` for non-ASCII), NFC, whole-float->int, lowercase `\u00xx` control escapes |
| Signature encoding | base64url (accept padded/unpadded, both alphabets) |
| Ed25519 | RFC 8032 verify over canonical bytes (VC/VP) or JWS signing input (delegation) |
| did:key | base58btc multibase `z` + multicodec `0xED01` + 32-byte pubkey |
| VC signed fields | object minus `proof` and `credentialStatus` |
| VP signed fields | object minus `proof` |
| Delegation | JWS EdDSA over `b64url(header).b64url(payload)`; `prf` recursion; `att` subset attenuation |
