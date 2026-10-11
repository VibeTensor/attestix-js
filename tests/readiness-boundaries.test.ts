import { generateKeyPairSync, sign } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import { verifyCredential, verifyPresentation } from '../src/verify/credential.js';
import { publicKeyToDidKey } from '../src/verify/didkey.js';
import { canonicalize, canonicalizeToString, parseCanonicalJson, type JsonValue } from '../src/verify/jcs.js';

function signed(kind: 'credential' | 'presentation', impersonate = false, expiry?: JsonValue) {
 const attacker = generateKeyPairSync('ed25519');
 const victim = generateKeyPairSync('ed25519');
 const did = publicKeyToDidKey(attacker.publicKey.export({format:'der',type:'spki'}).subarray(-32));
 const victimDid = publicKeyToDidKey(victim.publicKey.export({format:'der',type:'spki'}).subarray(-32));
 const claimed = impersonate ? victimDid : did;
 const payload: Record<string, JsonValue> = kind === 'credential'
  ? {type:['VerifiableCredential'], issuer:{id:claimed}, credentialSubject:{id:'synthetic'}}
  : {type:['VerifiablePresentation'], holder:claimed, verifiableCredential:[signed('credential')]};
 if (expiry !== undefined) payload.expirationDate = expiry;
 return {...payload, proof:{verificationMethod:`${did}#${did.slice(8)}`, proofValue:sign(null,canonicalize(payload),attacker.privateKey).toString('base64url')}};
}

describe('readiness verifier boundaries', () => {
 it('rejects malformed credential key metadata', () => {
  const credential = signed('credential');
  expect(verifyCredential({...credential, proof:{...credential.proof, verificationMethod:123}}).valid).toBe(false);
 });
 it('rejects malformed presentation key metadata', () => {
  const presentation = signed('presentation');
  expect(verifyPresentation({...presentation, proof:{...presentation.proof, verificationMethod:123}}).valid).toBe(false);
 });
 it('accepts the holder signature', () => expect(verifyPresentation(signed('presentation')).valid).toBe(true));
 it('rejects a signature impersonating a different holder', () => expect(verifyPresentation(signed('presentation', true)).valid).toBe(false));
 it.each([null,false,123,'','invalid-date'])('rejects malformed expiry %s', (expiry) => expect(verifyCredential(signed('credential',false,expiry)).valid).toBe(false));
 it('rejects an invalid verification time', () => expect(verifyCredential(signed('credential',false,'2030-01-01T00:00:00Z'),{now:NaN}).valid).toBe(false));
 it('rejects normalized key collisions', () => expect(() => canonicalize({'\u00e9':1,'e\u0301':2})).toThrow());
 it('sorts normalized object keys', () => expect(canonicalizeToString({'\u212b':1,Z:2})).toBe('{"Z":2,"\u00c5":1}'));
 it('rejects unsafe rounded integers', () => expect(() => canonicalize(Number.MAX_SAFE_INTEGER+1)).toThrow());
 it('preserves parsed integer precision when source access is available', () => {
  let sourceAvailable = false;
  JSON.parse('1', (_key, value, context?: {source?: string}) => {
   sourceAvailable = typeof context?.source === 'string';
   return value;
  });
  if (sourceAvailable) expect(canonicalizeToString(parseCanonicalJson('9007199254740993'))).toBe('9007199254740993');
  else expect(() => parseCanonicalJson('9007199254740993')).toThrow('source unavailable');
 });
 it('rejects precision loss on engines without integer source access', () => {
  const original = JSON.parse;
  const spy = vi.spyOn(JSON, 'parse').mockImplementation((text, reviver) =>
   original(text, reviver ? (key, value) => reviver(key, value) : undefined));
  try { expect(() => parseCanonicalJson('9007199254740993')).toThrow('source unavailable'); }
  finally { spy.mockRestore(); }
 });
});
