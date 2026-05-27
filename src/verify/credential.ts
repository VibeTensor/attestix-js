/**
 * Offline verification of Attestix W3C Verifiable Credentials and Verifiable
 * Presentations. Reproduces the Python engine's signing rules (see SPEC.md
 * §5/§6): the signature covers the credential object with `proof` and
 * `credentialStatus` removed, canonicalized via the JCS rules, verified with
 * the issuer's did:key Ed25519 public key.
 */

import { canonicalize, type JsonValue } from './jcs.js';
import { base64urlDecode } from './base64url.js';
import { didKeyToPublicKey, didFromVerificationMethod } from './didkey.js';
import { verifyEd25519 } from './ed25519.js';

/** Per-check booleans mirroring the Python verifier's `checks` object. */
export interface CredentialChecks {
	structure_valid: boolean;
	signature_valid: boolean;
	not_expired: boolean;
	/** Revocation cannot be confirmed offline; true unless embedded status says revoked. */
	not_revoked: boolean;
}

export interface VerifyCredentialResult {
	valid: boolean;
	reason?: string;
	checks: CredentialChecks;
	issuer?: string;
	subject?: string;
	type?: string[];
}

export interface VerifyCredentialOptions {
	/** Override "now" for expiry checks (ms epoch). Defaults to Date.now(). */
	now?: number;
	/** If false, skip the expirationDate check. Default true. */
	checkExpiry?: boolean;
}

type JsonObject = { [key: string]: JsonValue };

/** Fields excluded from the credential signature (Python MUTABLE_FIELDS). */
const VC_MUTABLE_FIELDS = ['proof', 'credentialStatus'];

function isObject(v: unknown): v is JsonObject {
	return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function stripFields(obj: JsonObject, fields: string[]): JsonObject {
	const out: JsonObject = {};
	for (const k of Object.keys(obj)) {
		if (!fields.includes(k)) out[k] = obj[k];
	}
	return out;
}

/**
 * Verify a single VC's Ed25519 proof, structure, expiry, and embedded
 * revocation status — without contacting the Attestix API.
 */
export function verifyCredential(
	credential: unknown,
	options: VerifyCredentialOptions = {},
): VerifyCredentialResult {
	const checks: CredentialChecks = {
		structure_valid: false,
		signature_valid: false,
		not_expired: false,
		not_revoked: true,
	};

	if (!isObject(credential)) {
		return { valid: false, reason: 'Credential is not an object', checks };
	}

	const type = credential.type;
	const types = Array.isArray(type) ? (type as string[]) : [];
	if (!types.includes('VerifiableCredential')) {
		return { valid: false, reason: 'Not a VerifiableCredential', checks };
	}
	checks.structure_valid = true;

	// Embedded revocation status (offline can only read what's present).
	const status = credential.credentialStatus;
	if (isObject(status) && status.revoked === true) {
		checks.not_revoked = false;
	}

	// Expiry.
	const checkExpiry = options.checkExpiry !== false;
	const expStr = credential.expirationDate;
	if (checkExpiry && typeof expStr === 'string') {
		const exp = Date.parse(expStr);
		const now = options.now ?? Date.now();
		checks.not_expired = Number.isNaN(exp) ? true : now < exp;
	} else {
		checks.not_expired = true;
	}

	// Signature.
	const proof = credential.proof;
	let issuer: string | undefined;
	if (isObject(proof) && typeof proof.proofValue === 'string') {
		const vm =
			typeof proof.verificationMethod === 'string'
				? proof.verificationMethod
				: '';
		let issuerDid = vm ? didFromVerificationMethod(vm) : '';
		if (!issuerDid && isObject(credential.issuer)) {
			const iid = (credential.issuer as JsonObject).id;
			if (typeof iid === 'string') issuerDid = iid;
		}
		issuer = issuerDid;
		try {
			const payload = stripFields(credential, VC_MUTABLE_FIELDS);
			const message = canonicalize(payload);
			const sig = base64urlDecode(proof.proofValue);
			const pub = didKeyToPublicKey(issuerDid);
			checks.signature_valid = verifyEd25519(sig, message, pub);
		} catch {
			checks.signature_valid = false;
		}
	}

	const subjectId =
		isObject(credential.credentialSubject) &&
		typeof (credential.credentialSubject as JsonObject).id === 'string'
			? ((credential.credentialSubject as JsonObject).id as string)
			: undefined;

	const valid =
		checks.structure_valid &&
		checks.signature_valid &&
		checks.not_expired &&
		checks.not_revoked;

	const result: VerifyCredentialResult = {
		valid,
		checks,
		type: types,
	};
	if (issuer !== undefined) result.issuer = issuer;
	if (subjectId !== undefined) result.subject = subjectId;
	if (!valid) {
		result.reason = !checks.signature_valid
			? 'Invalid signature'
			: !checks.not_expired
				? 'Credential expired'
				: !checks.not_revoked
					? 'Credential revoked'
					: 'Verification failed';
	}
	return result;
}

export interface VerifyPresentationResult {
	valid: boolean;
	reason?: string;
	holder?: string;
	vpSignatureValid: boolean;
	credentialCount: number;
	credentialResults: VerifyCredentialResult[];
}

/**
 * Verify a Verifiable Presentation: the holder's proof (signed payload is the
 * VP minus `proof` only) plus every embedded credential.
 */
export function verifyPresentation(
	presentation: unknown,
	options: VerifyCredentialOptions = {},
): VerifyPresentationResult {
	const empty: VerifyPresentationResult = {
		valid: false,
		vpSignatureValid: false,
		credentialCount: 0,
		credentialResults: [],
	};

	if (!isObject(presentation)) {
		return { ...empty, reason: 'Presentation is not an object' };
	}
	const types = Array.isArray(presentation.type)
		? (presentation.type as string[])
		: [];
	if (!types.includes('VerifiablePresentation')) {
		return { ...empty, reason: 'Not a VerifiablePresentation' };
	}

	const holder =
		typeof presentation.holder === 'string'
			? presentation.holder
			: undefined;

	// VP proof: signed payload excludes only `proof`.
	let vpSignatureValid = false;
	const proof = presentation.proof;
	if (isObject(proof) && typeof proof.proofValue === 'string') {
		const vm =
			typeof proof.verificationMethod === 'string'
				? proof.verificationMethod
				: '';
		const issuerDid = vm ? didFromVerificationMethod(vm) : holder ?? '';
		try {
			const payload = stripFields(presentation, ['proof']);
			const message = canonicalize(payload);
			const sig = base64urlDecode(proof.proofValue);
			const pub = didKeyToPublicKey(issuerDid);
			vpSignatureValid = verifyEd25519(sig, message, pub);
		} catch {
			vpSignatureValid = false;
		}
	}

	const creds = Array.isArray(presentation.verifiableCredential)
		? presentation.verifiableCredential
		: [];
	const credentialResults = creds.map((c) => verifyCredential(c, options));

	const credsValid = credentialResults.every((r) => r.valid);
	const valid = vpSignatureValid && credsValid;

	const result: VerifyPresentationResult = {
		valid,
		vpSignatureValid,
		credentialCount: creds.length,
		credentialResults,
	};
	if (holder !== undefined) result.holder = holder;
	if (!valid) {
		result.reason = !vpSignatureValid
			? 'Invalid presentation signature'
			: 'One or more embedded credentials failed verification';
	}
	return result;
}
