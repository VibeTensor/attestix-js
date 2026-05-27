/**
 * Offline verification of Attestix UCAN-style delegation chains.
 *
 * Delegations are EdDSA-signed JWTs (see SPEC.md §7). A token is a compact JWS:
 *   base64url(header) "." base64url(payload) "." base64url(signature)
 * The signature is Ed25519 over the ASCII signing input
 * `b64url(header).b64url(payload)`, verified with the `iss` did:key's public
 * key. The proof chain lives in the `prf` claim (a list of parent JWT strings).
 *
 * This reproduces `DelegationService.verify_delegation` (recursive prf
 * verification + cycle detection + expiry) AND the capability-attenuation rule
 * that the Python engine enforces at creation time
 * (`create_delegation`): a child's `att` must be a subset of every parent's
 * `att`. An offline verifier re-checks attenuation because it cannot trust that
 * the creation-time guard ran.
 */

import { base64urlDecode } from './base64url.js';
import { didKeyToPublicKey } from './didkey.js';
import { verifyEd25519 } from './ed25519.js';

export interface DelegationClaims {
	iss: string;
	aud?: string;
	sub?: string;
	delegator?: string;
	iat?: number;
	nbf?: number;
	exp?: number;
	jti?: string;
	att: string[];
	prf: string[];
	typ?: string;
	[key: string]: unknown;
}

export interface DelegationLinkResult {
	jti?: string;
	issuer: string;
	delegator?: string;
	audience?: string;
	capabilities: string[];
	signatureValid: boolean;
	expired: boolean;
	notYetValid: boolean;
}

export interface VerifyDelegationResult {
	valid: boolean;
	reason?: string;
	/** Per-link results, leaf first (matching the order the chain is walked). */
	links: DelegationLinkResult[];
	/** The capabilities held by the leaf (effective granted set). */
	capabilities: string[];
}

export interface VerifyDelegationOptions {
	/** Override "now" in unix seconds. Defaults to current time. */
	now?: number;
	/** Clock skew tolerance in seconds for exp/nbf. Default 0. */
	clockToleranceSeconds?: number;
}

interface DecodedToken {
	claims: DelegationClaims;
	signingInput: Uint8Array;
	signature: Uint8Array;
}

function decodeJwt(token: string): DecodedToken {
	const parts = token.split('.');
	if (parts.length !== 3) {
		throw new Error('Malformed JWT (expected 3 dot-separated segments)');
	}
	const [h, p, s] = parts;
	const payloadJson = new TextDecoder().decode(base64urlDecode(p));
	const claims = JSON.parse(payloadJson) as DelegationClaims;
	if (!Array.isArray(claims.att)) claims.att = [];
	if (!Array.isArray(claims.prf)) claims.prf = [];
	// JWS signing input is the ASCII bytes of "header.payload" exactly as
	// transmitted (no re-encoding of header/payload).
	const signingInput = new TextEncoder().encode(`${h}.${p}`);
	const signature = base64urlDecode(s);
	return { claims, signingInput, signature };
}

function isSubset(child: string[], parent: string[]): boolean {
	const parentSet = new Set(parent);
	return child.every((c) => parentSet.has(c));
}

/**
 * Verify a delegation token and its full proof chain.
 *
 * @param token Either a single leaf JWT string (its `prf` chain is walked
 *   internally) or an array of JWT strings ordered leaf..root. When an array
 *   is given, the leaf's `prf` linkage is still validated against the provided
 *   parents.
 */
export function verifyDelegationChain(
	token: string | string[],
	options: VerifyDelegationOptions = {},
): VerifyDelegationResult {
	const now = options.now ?? Math.floor(Date.now() / 1000);
	const tol = options.clockToleranceSeconds ?? 0;
	const links: DelegationLinkResult[] = [];

	if (Array.isArray(token)) {
		if (token.length === 0) {
			return {
				valid: false,
				reason: 'Empty delegation chain',
				links,
				capabilities: [],
			};
		}
		// Verify each provided link independently, then enforce linkage +
		// attenuation between consecutive links (leaf..root order).
		const decoded: DecodedToken[] = [];
		for (const t of token) {
			let d: DecodedToken;
			try {
				d = decodeJwt(t);
			} catch (e) {
				return {
					valid: false,
					reason: `Malformed token in chain: ${(e as Error).message}`,
					links,
					capabilities: [],
				};
			}
			decoded.push(d);
		}
		for (const d of decoded) {
			const link = verifySingle(d, now, tol);
			links.push(link);
			if (!link.signatureValid) {
				return { valid: false, reason: 'Invalid signature in chain', links, capabilities: [] };
			}
			if (link.expired) {
				return { valid: false, reason: 'A delegation in the chain has expired', links, capabilities: [] };
			}
			if (link.notYetValid) {
				return { valid: false, reason: 'A delegation in the chain is not yet valid (nbf)', links, capabilities: [] };
			}
		}
		// Attenuation + linkage across consecutive links (child = i, parent = i+1).
		for (let i = 0; i < decoded.length - 1; i++) {
			const child = decoded[i].claims;
			const parent = decoded[i + 1].claims;
			if (!isSubset(child.att, parent.att)) {
				return {
					valid: false,
					reason: 'Capability escalation: child att is not a subset of parent att',
					links,
					capabilities: [],
				};
			}
		}
		return { valid: true, links, capabilities: decoded[0].claims.att };
	}

	// Single token: walk its prf chain recursively.
	const seen = new Set<string>();
	const result = verifyRecursive(token, now, tol, seen, links, null);
	if (!result.ok) {
		return { valid: false, reason: result.reason, links, capabilities: [] };
	}
	return { valid: true, links, capabilities: links[0]?.capabilities ?? [] };
}

interface RecursiveResult {
	ok: boolean;
	reason?: string;
	att?: string[];
}

function verifyRecursive(
	token: string,
	now: number,
	tol: number,
	seen: Set<string>,
	links: DelegationLinkResult[],
	childAtt: string[] | null,
): RecursiveResult {
	let decoded: DecodedToken;
	try {
		decoded = decodeJwt(token);
	} catch (e) {
		return { ok: false, reason: `Malformed token: ${(e as Error).message}` };
	}

	const link = verifySingle(decoded, now, tol);
	links.push(link);

	if (link.jti) {
		if (seen.has(link.jti)) {
			return { ok: false, reason: 'Cycle detected in delegation proof chain' };
		}
		seen.add(link.jti);
	}
	if (!link.signatureValid) {
		return { ok: false, reason: 'Invalid token signature' };
	}
	if (link.expired) {
		return { ok: false, reason: 'Token has expired' };
	}
	if (link.notYetValid) {
		return { ok: false, reason: 'Token is not yet valid (nbf)' };
	}

	const att = decoded.claims.att;
	// Attenuation: this link is the parent of `childAtt`; child must be subset.
	if (childAtt !== null && !isSubset(childAtt, att)) {
		return {
			ok: false,
			reason: 'Capability escalation: child att is not a subset of parent att',
		};
	}

	// Recurse into every parent in prf.
	for (const parentToken of decoded.claims.prf) {
		if (typeof parentToken !== 'string' || !parentToken) {
			return { ok: false, reason: 'Malformed parent token in proof chain' };
		}
		const parentResult = verifyRecursive(
			parentToken,
			now,
			tol,
			seen,
			links,
			att,
		);
		if (!parentResult.ok) {
			return {
				ok: false,
				reason: `Invalid parent in proof chain: ${parentResult.reason}`,
			};
		}
	}

	return { ok: true, att };
}

function verifySingle(
	decoded: DecodedToken,
	now: number,
	tol: number,
): DelegationLinkResult {
	const c = decoded.claims;
	let signatureValid = false;
	try {
		const pub = didKeyToPublicKey(c.iss);
		signatureValid = verifyEd25519(
			decoded.signature,
			decoded.signingInput,
			pub,
		);
	} catch {
		signatureValid = false;
	}

	const expired = typeof c.exp === 'number' ? c.exp + tol < now : false;
	const notYetValid = typeof c.nbf === 'number' ? c.nbf - tol > now : false;

	const link: DelegationLinkResult = {
		issuer: c.iss,
		capabilities: c.att,
		signatureValid,
		expired,
		notYetValid,
	};
	if (c.jti !== undefined) link.jti = c.jti;
	if (c.delegator !== undefined) link.delegator = c.delegator;
	if (c.aud !== undefined) link.audience = c.aud;
	return link;
}

/** Decode a delegation JWT's claims WITHOUT verifying the signature. */
export function decodeDelegationUnsafe(token: string): DelegationClaims {
	return decodeJwt(token).claims;
}
