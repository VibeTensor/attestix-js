import { describe, expect, it } from 'vitest';
import { base64urlDecode } from '../src/verify/base64url.js';

const bytes = (...xs: number[]) => new Uint8Array(xs);

describe('base64urlDecode', () => {
	it('decodes url-safe input without padding', () => {
		expect(base64urlDecode('-_8')).toEqual(bytes(0xfb, 0xff));
	});

	it('decodes standard alphabet with padding', () => {
		expect(base64urlDecode('+/8=')).toEqual(bytes(0xfb, 0xff));
	});

	it('strips whitespace and trailing padding', () => {
		expect(base64urlDecode('  aGk=\n')).toEqual(bytes(0x68, 0x69));
		expect(base64urlDecode('aGk===')).toEqual(bytes(0x68, 0x69));
	});

	it('decodes empty and all-padding input to empty bytes', () => {
		expect(base64urlDecode('')).toEqual(bytes());
		expect(base64urlDecode('====')).toEqual(bytes());
	});

	it('rejects invalid characters, including non-ASCII', () => {
		expect(() => base64urlDecode('ab$c')).toThrow(/Invalid base64url character at index 2/);
		expect(() => base64urlDecode('ab\u00e9c')).toThrow(/index 2/);
	});

	it('rejects padding that is not trailing', () => {
		expect(() => base64urlDecode('a=b')).toThrow(/index 1/);
	});

	it('handles adversarial padding-heavy input in linear time', () => {
		const input = '='.repeat(200_000) + 'x';
		const start = Date.now();
		expect(() => base64urlDecode(input)).toThrow();
		expect(Date.now() - start).toBeLessThan(1000);
	});
});
