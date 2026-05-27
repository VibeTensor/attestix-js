# @vibetensor/attestix

TypeScript SDK for [Attestix](https://github.com/VibeTensor/attestix) - Attestation Infrastructure for AI Agents.

Provides typed client methods for identity management, verifiable credentials, compliance tracking, reputation scoring, provenance recording, delegation chains, DID operations, and blockchain anchoring.

## Installation

```bash
npm install @vibetensor/attestix
```

## Quick Start

```typescript
import { AttestixClient } from '@vibetensor/attestix';

const client = new AttestixClient({
  baseUrl: 'https://api.attestix.io',
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
console.log(result.valid); // true
```

## Offline verification (cross-engine interop)

Since v0.2.0 the package can verify Attestix Ed25519-signed **W3C Verifiable
Credentials / Presentations** and **UCAN-style delegation chains** entirely
offline — no API call, in Node or the browser. The canonical-JSON rules,
`did:key` codec, and signed-field sets are byte-compatible with the Python
Attestix engine, so a credential or delegation issued by the Python server
verifies in JS/TS and vice-versa. This is the cross-engine interop path tracked
in [attestix#7](https://github.com/VibeTensor/attestix/issues/7); the exact wire
format and canonicalization rules are documented in [`SPEC.md`](./SPEC.md).

It adds one small, audited dependency (`@noble/curves`) for Ed25519 and no
network access.

### Verify a credential

```typescript
import { verifyCredential } from '@vibetensor/attestix';

// `vc` is the raw VC JSON (e.g. from issueCredential, a file, or a QR payload)
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

`verifyCredential` recomputes the canonical bytes over the signed fields
(everything except the mutable `proof` and `credentialStatus`), then verifies
the `Ed25519Signature2020` proof against the issuer's `did:key`. Revocation can
only be confirmed against the embedded `credentialStatus`; live revocation is a
server-side lookup, so `not_revoked` reflects only what is present in the
document offline.

### Verify a delegation chain

```typescript
import { verifyDelegationChain } from '@vibetensor/attestix';

// Pass the leaf JWT (its `prf` parent chain is walked automatically),
// or an explicit array of tokens ordered leaf..root.
const result = verifyDelegationChain(leafToken);

if (result.valid) {
  console.log('Effective capabilities:', result.capabilities);
  console.log('Chain length:', result.links.length);
}
```

`verifyDelegationChain` verifies every link's EdDSA JWS signature against its
issuer `did:key`, walks the full `prf` proof chain, detects cycles, enforces
expiry/`nbf`, and re-checks **capability attenuation** (each child's `att` must
be a subset of its parent's `att`) so a forged chain that escalates scope is
rejected.

### Lower-level primitives

The canonicalizer, `did:key` codec, and raw Ed25519 verify are also exported:

```typescript
import {
  canonicalize,        // JSON value -> canonical UTF-8 bytes (Python-compatible)
  didKeyToPublicKey,   // did:key:z... -> 32-byte Ed25519 public key
  publicKeyToDidKey,   // 32-byte Ed25519 public key -> did:key:z...
  verifyEd25519,       // (signature, message, publicKey) -> boolean
  verifyPresentation,  // verify a Verifiable Presentation + its embedded VCs
} from '@vibetensor/attestix';
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
| `verifyDelegationChain(token \| tokens, options?)` | Verify a UCAN/JWT delegation chain (signatures, attenuation, expiry, cycles) |
| `canonicalize(value)` | Canonical UTF-8 bytes matching the Python engine's JCS form |
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
} from '@vibetensor/attestix';

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
  baseUrl: 'https://api.attestix.io',  // Required: API server URL
  apiKey: 'your-api-key',               // Required: API key
  timeout: 30000,                        // Optional: request timeout in ms (default: 30000)
});
```

The SDK automatically retries on 429 (rate limit) and 503 (service unavailable) responses with exponential backoff.

## License

Apache-2.0

## Links

- [Attestix API Documentation](https://docs.attestix.io)
- [GitHub](https://github.com/VibeTensor/attestix-js)
- [VibeTensor](https://vibetensor.com)
