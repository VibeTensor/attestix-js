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
