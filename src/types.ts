// ============================================================================
// Client Options
// ============================================================================

export interface AttestixOptions {
	/** Base URL of the Attestix API server */
	baseUrl: string;
	/** API key for authentication */
	apiKey: string;
	/** Request timeout in milliseconds (default: 30000) */
	timeout?: number;
}

// ============================================================================
// Identity
// ============================================================================

export interface Identity {
	agent_id: string;
	name: string;
	type: string;
	did?: string;
	capabilities?: string[];
	metadata?: Record<string, unknown>;
	status: string;
	created_at: string;
	updated_at: string;
}

export interface CreateIdentityParams {
	name: string;
	type: string;
	capabilities?: string[];
	metadata?: Record<string, unknown>;
}

export interface ListIdentitiesParams {
	skip?: number;
	limit?: number;
	type?: string;
	status?: string;
}

export interface PurgeResult {
	agent_id: string;
	deleted_counts: Record<string, number>;
	message: string;
}

// ============================================================================
// Credentials
// ============================================================================

export interface Credential {
	credential_id: string;
	issuer: string;
	subject: string;
	type: string;
	claims: Record<string, unknown>;
	status: string;
	issued_at: string;
	expires_at?: string;
	revoked_at?: string;
	revocation_reason?: string;
}

export interface IssueCredentialParams {
	issuer: string;
	subject: string;
	type: string;
	claims: Record<string, unknown>;
	expires_in_days?: number;
}

export interface ListCredentialsParams {
	skip?: number;
	limit?: number;
	issuer?: string;
	subject?: string;
	type?: string;
	status?: string;
}

export interface Presentation {
	presentation_id: string;
	holder: string;
	credential_ids: string[];
	verifiable_credentials: Record<string, unknown>[];
	created_at: string;
}

export interface CreatePresentationParams {
	holder: string;
	credential_ids: string[];
}

// ============================================================================
// Compliance
// ============================================================================

export interface ComplianceProfile {
	profile_id: string;
	name: string;
	framework: string;
	requirements: ComplianceRequirement[];
	agent_id?: string;
	status: string;
	created_at: string;
	updated_at: string;
}

export interface ComplianceRequirement {
	requirement_id: string;
	name: string;
	description: string;
	category: string;
	status: string;
}

export interface CreateComplianceProfileParams {
	name: string;
	framework: string;
	agent_id?: string;
	requirements?: ComplianceRequirement[];
}

export interface ComplianceStatus {
	profile_id: string;
	overall_status: string;
	completion_percentage: number;
	requirements_met: number;
	requirements_total: number;
	last_assessed: string;
}

export interface Assessment {
	assessment_id: string;
	profile_id: string;
	requirement_id: string;
	status: string;
	evidence?: string;
	assessed_at: string;
	assessed_by: string;
}

export interface RecordAssessmentParams {
	profile_id: string;
	requirement_id: string;
	status: string;
	evidence?: string;
	assessed_by: string;
}

export interface Declaration {
	declaration_id: string;
	profile_id: string;
	framework: string;
	content: string;
	generated_at: string;
}

export interface GenerateDeclarationParams {
	profile_id: string;
	format?: string;
}

// ============================================================================
// Reputation
// ============================================================================

export interface ReputationScore {
	agent_id: string;
	overall_score: number;
	interaction_count: number;
	positive_count: number;
	negative_count: number;
	categories?: Record<string, number>;
	last_updated: string;
}

export interface RecordInteractionParams {
	agent_id: string;
	counterparty_id: string;
	interaction_type: string;
	outcome: string;
	score?: number;
	metadata?: Record<string, unknown>;
}

export interface QueryReputationParams {
	min_score?: number;
	max_score?: number;
	min_interactions?: number;
	skip?: number;
	limit?: number;
}

// ============================================================================
// Provenance
// ============================================================================

export interface ProvenanceEntry {
	entry_id: string;
	agent_id: string;
	type: string;
	data: Record<string, unknown>;
	recorded_at: string;
}

export interface RecordTrainingDataParams {
	agent_id: string;
	dataset_name: string;
	dataset_version: string;
	source: string;
	license?: string;
	metadata?: Record<string, unknown>;
}

export interface RecordModelLineageParams {
	agent_id: string;
	model_name: string;
	model_version: string;
	parent_model?: string;
	training_data_ids?: string[];
	metadata?: Record<string, unknown>;
}

export interface AuditEntry {
	entry_id: string;
	agent_id: string;
	action: string;
	details: Record<string, unknown>;
	timestamp: string;
	anchor_id?: string;
}

export interface LogActionParams {
	agent_id: string;
	action: string;
	details: Record<string, unknown>;
}

export interface AuditTrailParams {
	agent_id?: string;
	action?: string;
	start_time?: string;
	end_time?: string;
	skip?: number;
	limit?: number;
}

// ============================================================================
// Delegation
// ============================================================================

export interface Delegation {
	delegation_id: string;
	delegator: string;
	delegate: string;
	scope: string[];
	constraints?: Record<string, unknown>;
	token: string;
	status: string;
	created_at: string;
	expires_at?: string;
}

export interface CreateDelegationParams {
	delegator: string;
	delegate: string;
	scope: string[];
	constraints?: Record<string, unknown>;
	expires_in_hours?: number;
}

export interface ListDelegationsParams {
	delegator?: string;
	delegate?: string;
	status?: string;
	skip?: number;
	limit?: number;
}

// ============================================================================
// DID
// ============================================================================

export interface DIDDocument {
	id: string;
	type: string;
	controller?: string;
	verification_method?: VerificationMethod[];
	authentication?: string[];
	assertion_method?: string[];
	created: string;
}

export interface VerificationMethod {
	id: string;
	type: string;
	controller: string;
	public_key_multibase?: string;
	public_key_jwk?: Record<string, unknown>;
}

// ============================================================================
// Blockchain Anchoring
// ============================================================================

export interface AnchorReceipt {
	anchor_id: string;
	type: string;
	target_id: string;
	chain: string;
	transaction_hash?: string;
	block_number?: number;
	status: string;
	anchored_at: string;
}

export interface AnchorVerification {
	anchor_id: string;
	verified: boolean;
	chain: string;
	transaction_hash?: string;
	block_number?: number;
	data_integrity: boolean;
	verified_at: string;
}

export interface CostEstimate {
	chain: string;
	estimated_gas: number;
	estimated_cost_usd: number;
	currency: string;
}

// ============================================================================
// Shared
// ============================================================================

export interface VerificationResult {
	valid: boolean;
	checks: VerificationCheck[];
	verified_at: string;
}

export interface VerificationCheck {
	name: string;
	passed: boolean;
	message?: string;
}

export interface ErrorResponse {
	detail: string;
	status_code: number;
}
