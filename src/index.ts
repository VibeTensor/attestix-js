export { AttestixClient } from './client.js';

// Offline cross-engine verification (Ed25519 / JCS / did:key). Verify Attestix
// W3C VCs, VPs, and UCAN delegation chains in Node/browser without the API.
export {
	canonicalize,
	canonicalizeToString,
	JcsUnsupportedValueError,
	base64urlDecode,
	publicKeyToDidKey,
	didKeyToPublicKey,
	didFromVerificationMethod,
	base58btcEncode,
	base58btcDecode,
	ED25519_MULTICODEC_PREFIX,
	verifyEd25519,
	verifyCredential,
	verifyPresentation,
	verifyDelegationChain,
	decodeDelegationUnsafe,
} from './verify/index.js';

export type {
	JsonValue,
	CredentialChecks,
	VerifyCredentialResult,
	VerifyCredentialOptions,
	VerifyPresentationResult,
	DelegationClaims,
	DelegationLinkResult,
	VerifyDelegationResult,
	VerifyDelegationOptions,
} from './verify/index.js';

export {
	AttestixError,
	AttestixAuthError,
	AttestixNotFoundError,
	AttestixValidationError,
	AttestixRateLimitError,
} from './errors.js';

export type {
	// Client options
	AttestixOptions,

	// Identity
	Identity,
	CreateIdentityParams,
	ListIdentitiesParams,
	PurgeResult,

	// Credentials
	Credential,
	IssueCredentialParams,
	ListCredentialsParams,
	Presentation,
	CreatePresentationParams,

	// Compliance
	ComplianceProfile,
	ComplianceRequirement,
	CreateComplianceProfileParams,
	ComplianceStatus,
	Assessment,
	RecordAssessmentParams,
	Declaration,
	GenerateDeclarationParams,

	// Reputation
	ReputationScore,
	RecordInteractionParams,
	QueryReputationParams,

	// Provenance
	ProvenanceEntry,
	RecordTrainingDataParams,
	RecordModelLineageParams,
	AuditEntry,
	LogActionParams,
	AuditTrailParams,

	// Delegation
	Delegation,
	CreateDelegationParams,
	ListDelegationsParams,

	// DID
	DIDDocument,
	VerificationMethod,

	// Blockchain
	AnchorReceipt,
	AnchorVerification,
	CostEstimate,

	// Shared
	VerificationResult,
	VerificationCheck,
	ErrorResponse,
} from './types.js';
