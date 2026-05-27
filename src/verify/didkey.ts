/**
 * did:key encode/decode for Ed25519 keys, matching the Python engine's
 * `auth.crypto.public_key_to_did_key` / `did_key_to_public_key`.
 *
 *   did:key:z<base58btc(0xED01 || raw_pubkey_32)>
 *
 * Multibase prefix: literal 'z' (base58btc). Multicodec prefix for
 * ed25519-pub: bytes 0xED 0x01.
 */

/** Multicodec prefix for Ed25519 public key (varint 0xed01). */
export const ED25519_MULTICODEC_PREFIX = new Uint8Array([0xed, 0x01]);

const BASE58_ALPHABET =
	'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

const BASE58_MAP = (() => {
	const map = new Int16Array(128).fill(-1);
	for (let i = 0; i < BASE58_ALPHABET.length; i++) {
		map[BASE58_ALPHABET.charCodeAt(i)] = i;
	}
	return map;
})();

/** Encode bytes as base58btc (Bitcoin alphabet), preserving leading zeros. */
export function base58btcEncode(bytes: Uint8Array): string {
	if (bytes.length === 0) return '';
	let zeros = 0;
	while (zeros < bytes.length && bytes[zeros] === 0) zeros++;

	// Convert big-endian byte array to base58 via repeated division.
	const digits: number[] = [0];
	for (let i = zeros; i < bytes.length; i++) {
		let carry = bytes[i];
		for (let j = 0; j < digits.length; j++) {
			carry += digits[j] << 8;
			digits[j] = carry % 58;
			carry = (carry / 58) | 0;
		}
		while (carry > 0) {
			digits.push(carry % 58);
			carry = (carry / 58) | 0;
		}
	}

	let out = '1'.repeat(zeros);
	for (let i = digits.length - 1; i >= 0; i--) {
		out += BASE58_ALPHABET[digits[i]];
	}
	return out;
}

/** Decode a base58btc string to bytes, preserving leading '1' -> 0x00. */
export function base58btcDecode(str: string): Uint8Array {
	if (str.length === 0) return new Uint8Array(0);
	let zeros = 0;
	while (zeros < str.length && str[zeros] === '1') zeros++;

	const bytes: number[] = [0];
	for (let i = zeros; i < str.length; i++) {
		const c = str.charCodeAt(i);
		const val = c < 128 ? BASE58_MAP[c] : -1;
		if (val === -1) {
			throw new Error(`Invalid base58 character '${str[i]}' at index ${i}`);
		}
		let carry = val;
		for (let j = 0; j < bytes.length; j++) {
			carry += bytes[j] * 58;
			bytes[j] = carry & 0xff;
			carry >>= 8;
		}
		while (carry > 0) {
			bytes.push(carry & 0xff);
			carry >>= 8;
		}
	}

	const out = new Uint8Array(zeros + bytes.length);
	// bytes are little-endian here; reverse into big-endian after the zeros.
	for (let i = 0; i < bytes.length; i++) {
		out[zeros + i] = bytes[bytes.length - 1 - i];
	}
	return out;
}

/** Encode a raw 32-byte Ed25519 public key as a did:key identifier. */
export function publicKeyToDidKey(rawPublicKey: Uint8Array): string {
	if (rawPublicKey.length !== 32) {
		throw new Error(
			`Ed25519 public key must be 32 bytes, got ${rawPublicKey.length}`,
		);
	}
	const multicodec = new Uint8Array(2 + 32);
	multicodec.set(ED25519_MULTICODEC_PREFIX, 0);
	multicodec.set(rawPublicKey, 2);
	return `did:key:z${base58btcEncode(multicodec)}`;
}

/**
 * Extract the raw 32-byte Ed25519 public key from a did:key identifier.
 * Throws if the DID is not a did:key, lacks the 'z' multibase prefix, or does
 * not carry the Ed25519 multicodec prefix (0xED01).
 */
export function didKeyToPublicKey(did: string): Uint8Array {
	if (!did.startsWith('did:key:z')) {
		throw new Error(`Invalid did:key format: ${did}`);
	}
	const encoded = did.slice('did:key:z'.length);
	const decoded = base58btcDecode(encoded);
	if (
		decoded.length < 2 ||
		decoded[0] !== ED25519_MULTICODEC_PREFIX[0] ||
		decoded[1] !== ED25519_MULTICODEC_PREFIX[1]
	) {
		throw new Error('Not an Ed25519 did:key (wrong multicodec prefix)');
	}
	const raw = decoded.slice(2);
	if (raw.length !== 32) {
		throw new Error(
			`Decoded Ed25519 public key must be 32 bytes, got ${raw.length}`,
		);
	}
	return raw;
}

/**
 * Resolve the issuer DID from a proof's verificationMethod (the part before
 * '#'), matching the Python engine's `vm.split("#")[0]`.
 */
export function didFromVerificationMethod(vm: string): string {
	const idx = vm.indexOf('#');
	return idx === -1 ? vm : vm.slice(0, idx);
}
