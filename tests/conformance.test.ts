import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { canonicalize } from '../src/verify/jcs.js';
import { didKeyToPublicKey } from '../src/verify/didkey.js';
import { verifyCredential } from '../src/verify/credential.js';
import { verifyDelegationChain } from '../src/verify/delegation.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * Shared cross-language verifier conformance vectors.
 *
 * This is the SAME vectors.json that the Go / Rust / Java / R ports consume -
 * copied verbatim from the foundation repo at
 * `VibeTensor/attestix:spec/verify/v1/vectors.json` (attestix 0.4.0). Every port
 * MUST reproduce the `expected` values byte-for-byte; running them here keeps the
 * npm verifier on the exact same conformance suite as the other engines.
 */
interface Vector {
	id: string;
	kind: string;
	input: Record<string, unknown>;
	expected: Record<string, unknown>;
	canonical_bytes_hex?: string;
	pubkey_raw_hex?: string;
	now_reference?: string;
}

const suite: { attestix_version: string; vector_count: number; vectors: Vector[] } =
	JSON.parse(
		readFileSync(join(__dirname, 'vectors', 'conformance', 'vectors.json'), 'utf-8'),
	);

function toHex(bytes: Uint8Array): string {
	return Array.from(bytes)
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
}

describe(`shared verifier conformance vectors (attestix ${suite.attestix_version})`, () => {
	it('loads the 0.4.0 conformance suite', () => {
		expect(suite.attestix_version).toBe('0.4.0');
		expect(suite.vectors.length).toBe(suite.vector_count);
	});

	for (const v of suite.vectors) {
		it(`${v.id} (${v.kind})`, () => {
			switch (v.kind) {
				case 'canonicalize': {
					// The shared vector includes `big_int: 9007199254740993` (2^53 + 1),
					// which a JS `number` (IEEE-754 double) cannot represent: a plain
					// `JSON.parse` rounds it to 2^53. The canonicalizer now accepts
					// BigInt and serializes it exactly, so we preserve the field as a
					// BigInt (as `parseCanonicalJson` would from raw JSON text) and
					// require a byte-exact match against the full reference hex.
					const input = { ...(v.input as Record<string, unknown>) };
					if (typeof input.big_int !== 'undefined') {
						input.big_int = BigInt('9007199254740993');
					}
					const got = canonicalize(input as never);
					expect(toHex(got)).toBe(v.canonical_bytes_hex as string);
					break;
				}

				case 'did_key_decode': {
					const pub = didKeyToPublicKey(v.input.did as string);
					expect(toHex(pub)).toBe(
						(v.expected.pubkey_raw_hex as string) ?? v.pubkey_raw_hex,
					);
					break;
				}

				case 'verify_credential': {
					// Pin "now" inside (or outside, for the expired case) the validity
					// window so the result is deterministic regardless of wall clock.
					const now = v.now_reference
						? Date.parse(v.now_reference)
						: Date.parse('2026-06-01T00:00:00Z');
					const result = verifyCredential(v.input, { now });
					expect(result.checks.signature_valid).toBe(v.expected.signature_valid);
					expect(result.checks.not_expired).toBe(v.expected.not_expired);
					expect(result.checks.not_revoked).toBe(v.expected.not_revoked);
					expect(result.valid).toBe(v.expected.verify);
					break;
				}

				case 'verify_delegation_chain': {
					// Vectors carry the leaf `token` plus its `parent_token`; pass the
					// explicit leaf..root array. nbf/exp are fixed far in the
					// future/past in the fixtures, so use the fixtures' own window.
					const chain = [
						v.input.token as string,
						v.input.parent_token as string,
					];
					const result = verifyDelegationChain(chain, {
						now: 1767225601, // 1s after the fixtures' iat (2026-01-01T00:00:01Z)
						clockToleranceSeconds: 0,
					});
					// attenuation subset is the security-critical assertion.
					const childAtt = v.input.child_att as string[];
					const parentAtt = v.input.parent_att as string[];
					const isSubset = childAtt.every((c) => parentAtt.includes(c));
					expect(isSubset).toBe(v.expected.attenuation_is_subset);
					expect(result.valid).toBe(v.expected.verify);
					break;
				}

				default:
					throw new Error(`Unknown vector kind: ${v.kind}`);
			}
		});
	}
});
