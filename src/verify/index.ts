/**
 * Offline, cross-engine verification of Attestix artifacts.
 *
 * These functions verify Ed25519-signed W3C Verifiable Credentials /
 * Presentations and UCAN-style delegation chains produced by the Python
 * Attestix engine - entirely offline (no API call), in Node or the browser.
 * Canonicalization, did:key codec, and signed-field sets are byte-compatible
 * with the Python engine (see SPEC.md).
 */

export {
	canonicalize,
	canonicalizeToString,
	JcsUnsupportedValueError,
	type JsonValue,
} from './jcs.js';

export { base64urlDecode } from './base64url.js';

export {
	publicKeyToDidKey,
	didKeyToPublicKey,
	didFromVerificationMethod,
	base58btcEncode,
	base58btcDecode,
	ED25519_MULTICODEC_PREFIX,
} from './didkey.js';

export { verifyEd25519 } from './ed25519.js';

export {
	verifyCredential,
	verifyPresentation,
	type CredentialChecks,
	type VerifyCredentialResult,
	type VerifyCredentialOptions,
	type VerifyPresentationResult,
} from './credential.js';

export {
	verifyDelegationChain,
	decodeDelegationUnsafe,
	type DelegationClaims,
	type DelegationLinkResult,
	type VerifyDelegationResult,
	type VerifyDelegationOptions,
} from './delegation.js';
