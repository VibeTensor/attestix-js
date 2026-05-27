import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { canonicalize, canonicalizeToString, JcsUnsupportedValueError, type JsonValue } from '../src/verify/jcs.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

interface JcsVector {
	input: JsonValue;
	canonical_hex: string;
	canonical_utf8: string;
}

const vectors: JcsVector[] = JSON.parse(
	readFileSync(join(__dirname, 'vectors', 'jcs.json'), 'utf-8'),
);

function toHex(bytes: Uint8Array): string {
	return Array.from(bytes)
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
}

describe('JCS canonicalization — cross-engine parity with Python', () => {
	it('produces byte-identical canonical bytes for every Python vector', () => {
		expect(vectors.length).toBeGreaterThan(0);
		for (const v of vectors) {
			const bytes = canonicalize(v.input);
			expect(toHex(bytes)).toBe(v.canonical_hex);
			expect(canonicalizeToString(v.input)).toBe(v.canonical_utf8);
		}
	});

	it('sorts keys by code point (uppercase before lowercase)', () => {
		expect(canonicalizeToString({ b: 1, a: 2, A: 3, Z: 4, z: 5 })).toBe(
			'{"A":3,"Z":4,"a":2,"b":1,"z":5}',
		);
	});

	it('emits non-ASCII as raw UTF-8, not \\u escapes', () => {
		const bytes = canonicalize({ x: 'café' });
		// "café" -> 63 61 66 c3 a9 inside the value
		expect(toHex(bytes)).toContain('636166c3a9');
	});

	it('coerces whole-valued floats to integers', () => {
		expect(canonicalizeToString({ n: 1.0 })).toBe('{"n":1}');
		expect(canonicalizeToString({ n: 2.0 })).toBe('{"n":2}');
	});

	it('keeps non-integer floats', () => {
		expect(canonicalizeToString({ n: 1.5 })).toBe('{"n":1.5}');
	});

	it('escapes control chars and quotes/backslash as JSON', () => {
		expect(canonicalizeToString({ s: '\t\n\r"\\' })).toBe('{"s":"\\t\\n\\r\\"\\\\"}');
		expect(canonicalizeToString({ s: '' })).toBe('{"s":"\\u0001\\u001f"}');
	});

	it('does NOT escape forward slash, <, >, &', () => {
		expect(canonicalizeToString({ s: 'a/b<c>d&e' })).toBe('{"s":"a/b<c>d&e"}');
	});

	it('NFC-normalizes strings', () => {
		// "e" + combining acute (U+0301) NFC-normalizes to "é" (U+00E9).
		const decomposed = 'é';
		const composed = 'é';
		expect(canonicalizeToString({ s: decomposed })).toBe(
			canonicalizeToString({ s: composed }),
		);
	});

	it('rejects values that would diverge from Python (signed zero, exponential)', () => {
		expect(() => canonicalize({ n: -0 })).toThrow(JcsUnsupportedValueError);
		expect(() => canonicalize({ n: 1e21 })).toThrow(JcsUnsupportedValueError);
		expect(() => canonicalize({ n: 1e-7 })).toThrow(JcsUnsupportedValueError);
		expect(() => canonicalize({ n: NaN })).toThrow(JcsUnsupportedValueError);
		expect(() => canonicalize({ n: Infinity })).toThrow(JcsUnsupportedValueError);
	});
});
