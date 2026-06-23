import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
	publicKeyToDidKey,
	didKeyToPublicKey,
	base58btcEncode,
	base58btcDecode,
	didFromVerificationMethod,
} from '../src/verify/didkey.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

const keys: {
	server_did: string;
	server_public_key_hex: string;
} = JSON.parse(readFileSync(join(__dirname, 'vectors', 'keys.json'), 'utf-8'));

function fromHex(hex: string): Uint8Array {
	const out = new Uint8Array(hex.length / 2);
	for (let i = 0; i < out.length; i++) {
		out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
	}
	return out;
}

describe('did:key codec - parity with Python engine', () => {
	it('encodes the Python server public key to the same did:key', () => {
		const pub = fromHex(keys.server_public_key_hex);
		expect(publicKeyToDidKey(pub)).toBe(keys.server_did);
	});

	it('decodes the Python did:key back to the same public key bytes', () => {
		const pub = didKeyToPublicKey(keys.server_did);
		expect(Array.from(pub)).toEqual(Array.from(fromHex(keys.server_public_key_hex)));
	});

	it('round-trips encode/decode', () => {
		const pub = fromHex(keys.server_public_key_hex);
		expect(Array.from(didKeyToPublicKey(publicKeyToDidKey(pub)))).toEqual(
			Array.from(pub),
		);
	});

	it('base58btc round-trips arbitrary bytes incl. leading zeros', () => {
		const samples = [
			new Uint8Array([0, 0, 1, 2, 3]),
			new Uint8Array([255, 254, 253]),
			fromHex(keys.server_public_key_hex),
		];
		for (const s of samples) {
			expect(Array.from(base58btcDecode(base58btcEncode(s)))).toEqual(
				Array.from(s),
			);
		}
	});

	it('rejects non-Ed25519 / malformed did:key', () => {
		expect(() => didKeyToPublicKey('did:web:example.com')).toThrow();
		expect(() => didKeyToPublicKey('did:key:zAB')).toThrow();
	});

	it('extracts DID from verificationMethod (before #)', () => {
		expect(
			didFromVerificationMethod(`${keys.server_did}#${keys.server_did.slice(8)}`),
		).toBe(keys.server_did);
		expect(didFromVerificationMethod(keys.server_did)).toBe(keys.server_did);
	});
});
