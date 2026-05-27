/**
 * base64url decoding that accepts both the url-safe (`-_`) and standard
 * (`+/`) alphabets, with or without `=` padding. The Python engine emits
 * url-safe WITH padding (base64.urlsafe_b64encode); JWS emits url-safe
 * WITHOUT padding. Both are accepted.
 */

const STD_ALPHABET =
	'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

const DECODE = (() => {
	const table = new Int16Array(128).fill(-1);
	for (let i = 0; i < STD_ALPHABET.length; i++) {
		table[STD_ALPHABET.charCodeAt(i)] = i;
	}
	// url-safe aliases
	table['-'.charCodeAt(0)] = 62;
	table['_'.charCodeAt(0)] = 63;
	return table;
})();

export function base64urlDecode(input: string): Uint8Array {
	// Strip padding and any surrounding whitespace.
	const s = input.replace(/=+$/g, '').trim();
	const len = s.length;
	const outLen = Math.floor((len * 6) / 8);
	const out = new Uint8Array(outLen);
	let buffer = 0;
	let bits = 0;
	let pos = 0;
	for (let i = 0; i < len; i++) {
		const c = s.charCodeAt(i);
		const val = c < 128 ? DECODE[c] : -1;
		if (val === -1) {
			throw new Error(`Invalid base64url character at index ${i}`);
		}
		buffer = (buffer << 6) | val;
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			out[pos++] = (buffer >> bits) & 0xff;
		}
	}
	return out;
}
