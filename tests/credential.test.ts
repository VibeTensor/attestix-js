import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { verifyCredential } from '../src/verify/credential.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

function loadVc(): Record<string, unknown> {
	return JSON.parse(
		readFileSync(join(__dirname, 'vectors', 'credential.json'), 'utf-8'),
	);
}

// The fixture issuanceDate is 2026-05-27; verify with a fixed "now" inside the
// validity window so the test is stable over time.
const NOW = Date.parse('2026-06-01T00:00:00Z');

describe('verifyCredential - cross-engine VC verification', () => {
	it('accepts a valid Python-signed credential', () => {
		const vc = loadVc();
		const result = verifyCredential(vc, { now: NOW });
		expect(result.valid).toBe(true);
		expect(result.checks.signature_valid).toBe(true);
		expect(result.checks.structure_valid).toBe(true);
		expect(result.checks.not_expired).toBe(true);
		expect(result.checks.not_revoked).toBe(true);
		expect(result.issuer).toBe(vc.issuer && (vc.issuer as { id: string }).id);
	});

	it('rejects when a claim byte is flipped (tamper in credentialSubject)', () => {
		const vc = loadVc();
		(vc.credentialSubject as { riskTier: string }).riskTier = 'low';
		const result = verifyCredential(vc, { now: NOW });
		expect(result.valid).toBe(false);
		expect(result.checks.signature_valid).toBe(false);
	});

	it('rejects when a non-ASCII claim is altered (UTF-8/NFC sensitivity)', () => {
		const vc = loadVc();
		(vc.credentialSubject as { assessor: string }).assessor = 'Cafe Bengio resume';
		const result = verifyCredential(vc, { now: NOW });
		expect(result.valid).toBe(false);
		expect(result.checks.signature_valid).toBe(false);
	});

	it('rejects when the proofValue signature is corrupted', () => {
		const vc = loadVc();
		const proof = vc.proof as { proofValue: string };
		// Flip one base64 char.
		const pv = proof.proofValue;
		proof.proofValue = (pv[0] === 'A' ? 'B' : 'A') + pv.slice(1);
		const result = verifyCredential(vc, { now: NOW });
		expect(result.valid).toBe(false);
		expect(result.checks.signature_valid).toBe(false);
	});

	it('marks expired credentials invalid', () => {
		const vc = loadVc();
		const result = verifyCredential(vc, { now: Date.parse('2030-01-01T00:00:00Z') });
		expect(result.checks.not_expired).toBe(false);
		expect(result.valid).toBe(false);
	});

	it('honors embedded revocation status', () => {
		const vc = loadVc();
		(vc.credentialStatus as { revoked: boolean }).revoked = true;
		const result = verifyCredential(vc, { now: NOW });
		// credentialStatus is NOT signed, so signature stays valid, but the
		// embedded revoked flag flips overall validity.
		expect(result.checks.signature_valid).toBe(true);
		expect(result.checks.not_revoked).toBe(false);
		expect(result.valid).toBe(false);
	});

	it('rejects a non-credential object', () => {
		expect(verifyCredential({ foo: 'bar' }).valid).toBe(false);
		expect(verifyCredential(null).valid).toBe(false);
	});
});
