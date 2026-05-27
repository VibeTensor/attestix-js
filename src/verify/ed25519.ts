/**
 * Ed25519 signature verification (RFC 8032 / PureEdDSA), Node + browser
 * compatible, backed by the audited @noble/curves implementation.
 */

import { ed25519 } from '@noble/curves/ed25519.js';

/**
 * Verify an Ed25519 signature.
 *
 * @param signature 64-byte raw Ed25519 signature.
 * @param message   the exact bytes that were signed.
 * @param publicKey 32-byte raw Ed25519 public key.
 * @returns true iff the signature is valid; never throws on bad input — a
 *          malformed signature/key is treated as a failed verification.
 */
export function verifyEd25519(
	signature: Uint8Array,
	message: Uint8Array,
	publicKey: Uint8Array,
): boolean {
	try {
		if (signature.length !== 64 || publicKey.length !== 32) {
			return false;
		}
		return ed25519.verify(signature, message, publicKey);
	} catch {
		return false;
	}
}
