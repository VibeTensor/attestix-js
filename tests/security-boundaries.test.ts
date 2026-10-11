import { generateKeyPairSync, sign } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { verifyCredential } from '../src/verify/credential.js'
import { publicKeyToDidKey } from '../src/verify/didkey.js'
import { canonicalize, type JsonValue } from '../src/verify/jcs.js'

function signedCredential(impersonate = false, expirationDate = '2030-01-01T00:00:00Z') {
	const attacker = generateKeyPairSync('ed25519')
	const victim = generateKeyPairSync('ed25519')
	const attackerDid = publicKeyToDidKey(attacker.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32))
	const victimDid = publicKeyToDidKey(victim.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32))
	const payload = {
		type: ['VerifiableCredential'],
		issuer: { id: impersonate ? victimDid : attackerDid },
		credentialSubject: { id: 'audit-subject', approved: true },
		expirationDate,
	}
	return {
		...payload,
		proof: {
			verificationMethod: `${attackerDid}#${attackerDid.slice(8)}`,
			proofValue: sign(null, canonicalize(payload as JsonValue), attacker.privateKey).toString('base64url'),
		},
	}
}

describe('credential security boundaries', () => {
	it('accepts a signature made by the claimed issuer', () => {
		expect(verifyCredential(signedCredential()).valid).toBe(true)
	})
	it('rejects an attacker signature claiming a different issuer', () => {
		expect(verifyCredential(signedCredential(true)).valid).toBe(false)
	})
	it('rejects a signed credential with a malformed expiry', () => {
		expect(verifyCredential(signedCredential(false, 'invalid-date')).valid).toBe(false)
	})
})
