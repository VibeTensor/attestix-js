import {
	AttestixError,
	AttestixAuthError,
	AttestixNotFoundError,
	AttestixValidationError,
	AttestixRateLimitError,
} from './errors.js';

import type {
	AttestixOptions,
	Identity,
	CreateIdentityParams,
	ListIdentitiesParams,
	PurgeResult,
	Credential,
	IssueCredentialParams,
	ListCredentialsParams,
	Presentation,
	CreatePresentationParams,
	ComplianceProfile,
	CreateComplianceProfileParams,
	ComplianceStatus,
	Assessment,
	RecordAssessmentParams,
	Declaration,
	GenerateDeclarationParams,
	ReputationScore,
	RecordInteractionParams,
	QueryReputationParams,
	ProvenanceEntry,
	RecordTrainingDataParams,
	RecordModelLineageParams,
	AuditEntry,
	LogActionParams,
	AuditTrailParams,
	Delegation,
	CreateDelegationParams,
	ListDelegationsParams,
	DIDDocument,
	AnchorReceipt,
	AnchorVerification,
	CostEstimate,
	VerificationResult,
} from './types.js';

const DEFAULT_TIMEOUT = 30_000;
const RETRY_STATUS_CODES = new Set([429, 503]);
const MAX_RETRIES = 1;
const BASE_RETRY_DELAY = 1000;

export class AttestixClient {
	private readonly baseUrl: string;
	private readonly apiKey: string;
	private readonly timeout: number;

	constructor(options: AttestixOptions) {
		this.baseUrl = options.baseUrl.replace(/\/+$/, '');
		this.apiKey = options.apiKey;
		this.timeout = options.timeout ?? DEFAULT_TIMEOUT;
	}

	// ========================================================================
	// Identity
	// ========================================================================

	async createIdentity(params: CreateIdentityParams): Promise<Identity> {
		return this.request<Identity>('POST', '/identities', params);
	}

	async getIdentity(agentId: string): Promise<Identity> {
		return this.request<Identity>('GET', `/identities/${encodeURIComponent(agentId)}`);
	}

	async listIdentities(params?: ListIdentitiesParams): Promise<Identity[]> {
		const query = this.buildQuery(params);
		return this.request<Identity[]>('GET', `/identities${query}`);
	}

	async verifyIdentity(agentId: string): Promise<VerificationResult> {
		return this.request<VerificationResult>('POST', `/identities/${encodeURIComponent(agentId)}/verify`);
	}

	async translateIdentity(agentId: string, format: string): Promise<Record<string, unknown>> {
		const query = this.buildQuery({ format });
		return this.request<Record<string, unknown>>('GET', `/identities/${encodeURIComponent(agentId)}/translate${query}`);
	}

	async revokeIdentity(agentId: string, reason?: string): Promise<Identity> {
		return this.request<Identity>('POST', `/identities/${encodeURIComponent(agentId)}/revoke`, { reason });
	}

	async purgeAgentData(agentId: string): Promise<PurgeResult> {
		return this.request<PurgeResult>('DELETE', `/identities/${encodeURIComponent(agentId)}/purge`);
	}

	// ========================================================================
	// Credentials
	// ========================================================================

	async issueCredential(params: IssueCredentialParams): Promise<Credential> {
		return this.request<Credential>('POST', '/credentials', params);
	}

	async getCredential(credentialId: string): Promise<Credential> {
		return this.request<Credential>('GET', `/credentials/${encodeURIComponent(credentialId)}`);
	}

	async listCredentials(params?: ListCredentialsParams): Promise<Credential[]> {
		const query = this.buildQuery(params);
		return this.request<Credential[]>('GET', `/credentials${query}`);
	}

	async verifyCredential(credentialId: string): Promise<VerificationResult> {
		return this.request<VerificationResult>('POST', `/credentials/${encodeURIComponent(credentialId)}/verify`);
	}

	async verifyExternalCredential(credential: Record<string, unknown>): Promise<VerificationResult> {
		return this.request<VerificationResult>('POST', '/credentials/verify-external', credential);
	}

	async revokeCredential(credentialId: string, reason?: string): Promise<Credential> {
		return this.request<Credential>('POST', `/credentials/${encodeURIComponent(credentialId)}/revoke`, { reason });
	}

	async createPresentation(params: CreatePresentationParams): Promise<Presentation> {
		return this.request<Presentation>('POST', '/credentials/presentations', params);
	}

	// ========================================================================
	// Compliance
	// ========================================================================

	async createComplianceProfile(params: CreateComplianceProfileParams): Promise<ComplianceProfile> {
		return this.request<ComplianceProfile>('POST', '/compliance/profiles', params);
	}

	async getComplianceProfile(profileId: string): Promise<ComplianceProfile> {
		return this.request<ComplianceProfile>('GET', `/compliance/profiles/${encodeURIComponent(profileId)}`);
	}

	async listComplianceProfiles(): Promise<ComplianceProfile[]> {
		return this.request<ComplianceProfile[]>('GET', '/compliance/profiles');
	}

	async getComplianceStatus(profileId: string): Promise<ComplianceStatus> {
		return this.request<ComplianceStatus>('GET', `/compliance/profiles/${encodeURIComponent(profileId)}/status`);
	}

	async recordAssessment(params: RecordAssessmentParams): Promise<Assessment> {
		return this.request<Assessment>('POST', '/compliance/assessments', params);
	}

	async generateDeclaration(params: GenerateDeclarationParams): Promise<Declaration> {
		return this.request<Declaration>('POST', '/compliance/declarations', params);
	}

	// ========================================================================
	// Reputation
	// ========================================================================

	async recordInteraction(params: RecordInteractionParams): Promise<void> {
		await this.request<void>('POST', '/reputation/interactions', params);
	}

	async getReputation(agentId: string): Promise<ReputationScore> {
		return this.request<ReputationScore>('GET', `/reputation/${encodeURIComponent(agentId)}`);
	}

	async queryReputation(params?: QueryReputationParams): Promise<ReputationScore[]> {
		const query = this.buildQuery(params);
		return this.request<ReputationScore[]>('GET', `/reputation${query}`);
	}

	// ========================================================================
	// Provenance
	// ========================================================================

	async recordTrainingData(params: RecordTrainingDataParams): Promise<ProvenanceEntry> {
		return this.request<ProvenanceEntry>('POST', '/provenance/training-data', params);
	}

	async recordModelLineage(params: RecordModelLineageParams): Promise<ProvenanceEntry> {
		return this.request<ProvenanceEntry>('POST', '/provenance/model-lineage', params);
	}

	async logAction(params: LogActionParams): Promise<AuditEntry> {
		return this.request<AuditEntry>('POST', '/provenance/actions', params);
	}

	async getProvenance(agentId: string): Promise<ProvenanceEntry[]> {
		return this.request<ProvenanceEntry[]>('GET', `/provenance/${encodeURIComponent(agentId)}`);
	}

	async getAuditTrail(params?: AuditTrailParams): Promise<AuditEntry[]> {
		const query = this.buildQuery(params);
		return this.request<AuditEntry[]>('GET', `/provenance/audit${query}`);
	}

	// ========================================================================
	// Delegation
	// ========================================================================

	async createDelegation(params: CreateDelegationParams): Promise<Delegation> {
		return this.request<Delegation>('POST', '/delegations', params);
	}

	async listDelegations(params?: ListDelegationsParams): Promise<Delegation[]> {
		const query = this.buildQuery(params);
		return this.request<Delegation[]>('GET', `/delegations${query}`);
	}

	async verifyDelegation(token: string): Promise<VerificationResult> {
		return this.request<VerificationResult>('POST', '/delegations/verify', { token });
	}

	async revokeDelegation(delegationId: string): Promise<void> {
		await this.request<void>('POST', `/delegations/${encodeURIComponent(delegationId)}/revoke`);
	}

	// ========================================================================
	// DID
	// ========================================================================

	async createDidKey(): Promise<DIDDocument> {
		return this.request<DIDDocument>('POST', '/did/key');
	}

	async createDidWeb(domain: string): Promise<DIDDocument> {
		return this.request<DIDDocument>('POST', '/did/web', { domain });
	}

	async resolveDid(did: string): Promise<DIDDocument> {
		return this.request<DIDDocument>('GET', `/did/${encodeURIComponent(did)}`);
	}

	// ========================================================================
	// Blockchain Anchoring
	// ========================================================================

	async anchorIdentity(agentId: string): Promise<AnchorReceipt> {
		return this.request<AnchorReceipt>('POST', `/anchoring/identities/${encodeURIComponent(agentId)}`);
	}

	async anchorCredential(credentialId: string): Promise<AnchorReceipt> {
		return this.request<AnchorReceipt>('POST', `/anchoring/credentials/${encodeURIComponent(credentialId)}`);
	}

	async anchorAuditBatch(entryIds?: string[]): Promise<AnchorReceipt> {
		return this.request<AnchorReceipt>('POST', '/anchoring/audit-batch', { entry_ids: entryIds });
	}

	async verifyAnchor(anchorId: string): Promise<AnchorVerification> {
		return this.request<AnchorVerification>('POST', `/anchoring/${encodeURIComponent(anchorId)}/verify`);
	}

	async getAnchorStatus(anchorId: string): Promise<AnchorReceipt> {
		return this.request<AnchorReceipt>('GET', `/anchoring/${encodeURIComponent(anchorId)}`);
	}

	async estimateAnchorCost(): Promise<CostEstimate> {
		return this.request<CostEstimate>('GET', '/anchoring/estimate');
	}

	// ========================================================================
	// Internal
	// ========================================================================

	private async request<T>(
		method: string,
		path: string,
		body?: unknown,
	): Promise<T> {
		return this.requestWithRetry<T>(method, path, body, 0);
	}

	private async requestWithRetry<T>(
		method: string,
		path: string,
		body: unknown,
		attempt: number,
	): Promise<T> {
		const controller = new AbortController();
		const timeoutId = setTimeout(() => controller.abort(), this.timeout);

		const url = `${this.baseUrl}${path}`;
		const headers: Record<string, string> = {
			'Authorization': `Bearer ${this.apiKey}`,
			'Accept': 'application/json',
		};

		const init: RequestInit = {
			method,
			headers,
			signal: controller.signal,
		};

		if (body !== undefined && method !== 'GET') {
			headers['Content-Type'] = 'application/json';
			init.body = JSON.stringify(body);
		}

		let response: Response;

		try {
			response = await fetch(url, init);
		} catch (error) {
			clearTimeout(timeoutId);

			if (error instanceof DOMException && error.name === 'AbortError') {
				throw new AttestixError(
					`Request timed out after ${this.timeout}ms`,
					0,
					'Request timeout',
				);
			}

			throw new AttestixError(
				`Network error: ${error instanceof Error ? error.message : String(error)}`,
				0,
				'Network error',
			);
		} finally {
			clearTimeout(timeoutId);
		}

		// Retry on 429 or 503 with exponential backoff
		if (RETRY_STATUS_CODES.has(response.status) && attempt < MAX_RETRIES) {
			const retryAfter = response.headers.get('Retry-After');
			const delay = retryAfter
				? parseInt(retryAfter, 10) * 1000
				: BASE_RETRY_DELAY * Math.pow(2, attempt);

			await this.sleep(delay);
			return this.requestWithRetry<T>(method, path, body, attempt + 1);
		}

		if (!response.ok) {
			await this.handleErrorResponse(response);
		}

		// Handle 204 No Content
		if (response.status === 204) {
			return undefined as T;
		}

		const text = await response.text();
		if (!text) {
			return undefined as T;
		}

		return JSON.parse(text) as T;
	}

	private async handleErrorResponse(response: Response): Promise<never> {
		let detail: string;

		try {
			const body = await response.json();
			detail = body.detail ?? body.message ?? JSON.stringify(body);
		} catch {
			detail = `HTTP ${response.status}: ${response.statusText}`;
		}

		switch (response.status) {
			case 400:
				throw new AttestixValidationError(detail);
			case 401:
			case 403:
				throw new AttestixAuthError(detail);
			case 404:
				throw new AttestixNotFoundError(detail);
			case 429: {
				const retryAfter = response.headers.get('Retry-After');
				throw new AttestixRateLimitError(
					detail,
					retryAfter ? parseInt(retryAfter, 10) : undefined,
				);
			}
			default:
				throw new AttestixError(detail, response.status, detail);
		}
	}

	private buildQuery(params?: object): string {
		if (!params) return '';

		const searchParams = new URLSearchParams();
		const entries = Object.entries(params) as [string, unknown][];

		for (const [key, value] of entries) {
			if (value !== undefined && value !== null) {
				searchParams.set(key, String(value));
			}
		}

		const queryString = searchParams.toString();
		return queryString ? `?${queryString}` : '';
	}

	private sleep(ms: number): Promise<void> {
		return new Promise((resolve) => setTimeout(resolve, ms));
	}
}
