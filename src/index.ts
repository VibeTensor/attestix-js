export { AttestixClient } from './client.js';

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
