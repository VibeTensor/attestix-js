# attestix

TypeScript REST client and offline verifier for the
[Attestix core](https://github.com/VibeTensor/attestix). Offline functions verify
Ed25519 credentials and presentations plus UCAN-style delegation tokens without
contacting a server. Client methods call a configured API and require its
availability and authentication.

## Installation and source status

Requires Node 20.19.0 or later, as declared in [package.json](package.json).
The current source uses @noble/curves 2.2.0. Browser use also requires the APIs
used by the verifier, including TextEncoder/TextDecoder and Unicode normalization.

```sh
npm install attestix
```

The source manifest version is 0.4.2. This does not establish that a
registry release contains the current main-branch fixes. Select a reviewed
published version or build a reviewed checkout:

```sh
npm ci
npm run lint
npm test
npm run build
```

See [CHANGELOG.md](CHANGELOG.md) for the 0.4.2 release changes.

## Quick Start

```typescript
import { AttestixClient } from 'attestix';

const client = new AttestixClient({
  baseUrl: 'https://your-attestix-server.example',
  apiKey: 'your-api-key',
});

// Create an agent identity
const identity = await client.createIdentity({
  name: 'My AI Agent',
  type: 'autonomous',
  capabilities: ['text-generation', 'code-review'],
});

console.log(identity.agent_id);

// Issue a credential
const credential = await client.issueCredential({
  issuer: identity.agent_id,
  subject: identity.agent_id,
  type: 'SafetyAudit',
  claims: { passed: true, score: 95 },
});

// Verify it
const result = await client.verifyCredential(credential.credential_id);
console.log(result.valid); // The server's verification verdict
```

## Offline verification (cross-engine interop)

The offline functions accept raw credential/presentation objects or compact
JWT delegation tokens, separately from REST response records. Their signing
form is documented in [SPEC.md](SPEC.md). Compatibility is tested against the
vendored vectors and supported canonical values; arbitrary Python/JavaScript
floating-point equivalence is not guaranteed.

### Cross-language conformance

The shared [v1 contract](https://github.com/VibeTensor/attestix/tree/main/spec/verify/v1)
is represented by [vendored vectors](tests/vectors/conformance/vectors.json)
and [conformance tests](tests/conformance.test.ts). Those cases cover canonical
bytes, key decoding, valid/tampered/expired credentials, and delegation
attenuation. They do not prove every possible input or every port's policy.

### Verify a credential

```typescript
import { verifyCredential } from 'attestix';

// `vc` is a raw VerifiableCredential object, not an API credential record.
const result = verifyCredential(vc);

if (result.valid) {
  console.log('Issuer:', result.issuer);   // did:key:z...
  console.log('Subject:', result.subject);
} else {
  console.log('Invalid:', result.reason);   // e.g. "Invalid signature"
}

// Per-check detail:
// result.checks = { structure_valid, signature_valid, not_expired, not_revoked }
```

`verifyCredential` signs everything except top-level `proof` and
`credentialStatus`. It resolves the key from signed `issuer` or `issuer.id`;
a present verification method must be a nonempty string with the same issuer
DID before `#`. `verifyPresentation` instead binds the proof to signed `holder`
and checks every embedded credential.

By default, a present malformed expiry or non-finite `now` fails expiry;
absent expiry is allowed. `options.now` is milliseconds since epoch for
credentials and embedded credentials. `checkExpiry: false` intentionally skips
that check. A valid credential requires structure, signature, expiry, and
embedded revocation checks. Offline status is only the embedded boolean
`credentialStatus.revoked`; it does not establish live revocation state.

Invalid proof/key/canonicalization input returns a negative signature result.
Direct canonicalization throws for unsupported values. This is not a full W3C
schema validator or JSON-LD processor. Presentation verification does not check
expected challenge/domain, freshness, or replay policy; apply those checks
before relying on a holder authentication result.

### Verify a delegation chain

```typescript
import { verifyDelegationChain } from 'attestix';

// Pass the leaf JWT (its `prf` parent chain is walked automatically),
// or an explicit array of tokens ordered leaf..root.
const result = verifyDelegationChain(leafToken);

if (result.valid) {
  console.log('Effective capabilities:', result.capabilities);
  console.log('Chain length:', result.links.length);
}
```

For a single token, verification walks `prf`, checks each EdDSA signature,
numeric `exp` and `nbf`, repeated-`jti` cycles, and capability attenuation.
`options.now` uses Unix seconds here, unlike credential verification.

An explicit array is ordered leaf..root. That path checks listed signatures,
numeric time claims, and attenuation between consecutive tokens; it does not
independently enforce `prf` linkage or cycle detection. Use the single-token
recursive path when ancestry checks are required. Missing/non-numeric time
claims are not a required-expiry policy; apply required-claim and audience
policy in the application. Neither path performs live revocation checks.

### Lower-level primitives

The canonicalizer, `did:key` codec, and raw Ed25519 verify are also exported:

```typescript
import {
  canonicalize,        // Supported JSON value -> canonical UTF-8 bytes
  didKeyToPublicKey,   // did:key:z... -> 32-byte Ed25519 public key
  publicKeyToDidKey,   // 32-byte Ed25519 public key -> did:key:z...
  verifyEd25519,       // (signature, message, publicKey) -> boolean
  verifyPresentation,  // verify a Verifiable Presentation + its embedded VCs
} from 'attestix';
```

## API Reference

### Identity

| Method | Description |
|--------|-------------|
| `createIdentity(params)` | Register a new agent identity |
| `getIdentity(agentId)` | Retrieve an identity by agent ID |
| `listIdentities(params?)` | List identities with optional filters |
| `verifyIdentity(agentId)` | Verify an identity's validity |
| `translateIdentity(agentId, format)` | Translate identity to another format |
| `revokeIdentity(agentId, reason?)` | Revoke an identity |
| `purgeAgentData(agentId)` | Delete all data for an agent |

### Credentials

| Method | Description |
|--------|-------------|
| `issueCredential(params)` | Issue a new verifiable credential |
| `getCredential(credentialId)` | Retrieve a credential |
| `listCredentials(params?)` | List credentials with filters |
| `verifyCredential(credentialId)` | Verify a credential |
| `verifyExternalCredential(credential)` | Verify an externally-issued credential |
| `revokeCredential(credentialId, reason?)` | Revoke a credential |
| `createPresentation(params)` | Create a verifiable presentation |

### Compliance

| Method | Description |
|--------|-------------|
| `createComplianceProfile(params)` | Create a compliance profile |
| `getComplianceProfile(profileId)` | Get a compliance profile |
| `listComplianceProfiles()` | List all compliance profiles |
| `getComplianceStatus(profileId)` | Get compliance status |
| `recordAssessment(params)` | Record a compliance assessment |
| `generateDeclaration(params)` | Generate a declaration of conformity |

### Reputation

| Method | Description |
|--------|-------------|
| `recordInteraction(params)` | Record an agent interaction |
| `getReputation(agentId)` | Get reputation score for an agent |
| `queryReputation(params?)` | Query reputation scores with filters |

### Provenance

| Method | Description |
|--------|-------------|
| `recordTrainingData(params)` | Record training data provenance |
| `recordModelLineage(params)` | Record model lineage |
| `logAction(params)` | Log an auditable action |
| `getProvenance(agentId)` | Get provenance entries for an agent |
| `getAuditTrail(params?)` | Query the audit trail |

### Delegation

| Method | Description |
|--------|-------------|
| `createDelegation(params)` | Create a delegation chain |
| `listDelegations(params?)` | List delegations |
| `verifyDelegation(token)` | Verify a delegation token |
| `revokeDelegation(delegationId)` | Revoke a delegation |

### DID

| Method | Description |
|--------|-------------|
| `createDidKey()` | Create a did:key document |
| `createDidWeb(domain)` | Create a did:web document |
| `resolveDid(did)` | Resolve a DID to its document |

### Blockchain Anchoring

| Method | Description |
|--------|-------------|
| `anchorIdentity(agentId)` | Anchor an identity on-chain |
| `anchorCredential(credentialId)` | Anchor a credential on-chain |
| `anchorAuditBatch(entryIds?)` | Anchor a batch of audit entries |
| `verifyAnchor(anchorId)` | Verify an on-chain anchor |
| `getAnchorStatus(anchorId)` | Get anchor status |
| `estimateAnchorCost()` | Estimate anchoring cost |

### Offline Verification

| Function | Description |
|--------|-------------|
| `verifyCredential(vc, options?)` | Verify a W3C VC's Ed25519 proof, structure, and expiry offline |
| `verifyPresentation(vp, options?)` | Verify a VP's holder proof and every embedded credential offline |
| `verifyDelegationChain(token \| tokens, options?)` | Recursive proof verification for a leaf token, or listed-link verification for an explicit array |
| `canonicalize(value)` | Canonical bytes for supported v1 JSON values; throws on unsupported input |
| `didKeyToPublicKey(did)` / `publicKeyToDidKey(bytes)` | did:key (Ed25519) decode / encode |
| `verifyEd25519(sig, msg, pubKey)` | Raw Ed25519 signature verification |

## Error Handling

The SDK throws typed errors based on HTTP status codes:

```typescript
import {
  AttestixAuthError,
  AttestixNotFoundError,
  AttestixValidationError,
  AttestixRateLimitError,
} from 'attestix';

try {
  await client.getIdentity('nonexistent');
} catch (error) {
  if (error instanceof AttestixNotFoundError) {
    console.log('Agent not found');
  } else if (error instanceof AttestixAuthError) {
    console.log('Invalid API key');
  } else if (error instanceof AttestixRateLimitError) {
    console.log(`Rate limited, retry after ${error.retryAfter}s`);
  }
}
```

## Configuration

```typescript
const client = new AttestixClient({
  baseUrl: 'https://your-attestix-server.example',  // Required: API server URL
  apiKey: 'your-api-key',               // Required: API key
  timeout: 30000,                        // Optional: request timeout in ms (default: 30000)
});
```

The REST client retries once after a 429 or 503 response, using its configured
request timeout. The delay uses Retry-After when supplied, otherwise one second.
Other failures use the typed
HTTP error surface. The API itself determines authorization and availability.

## License

Apache-2.0

## Links

- [Attestix core](https://github.com/VibeTensor/attestix)
- [Verifier conformance spec](https://github.com/VibeTensor/attestix/tree/main/spec/verify/v1): shared cross-language vectors + canonical-form rules
- [Attestix Documentation](https://attestix.io/docs)
- [GitHub (this package)](https://github.com/VibeTensor/attestix-js)
- [VibeTensor](https://vibetensor.com)
