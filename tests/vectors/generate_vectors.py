r"""Generate cross-engine test vectors from the REAL Python Attestix engine.

Run from the Attestix Python repo root so `auth.crypto` is importable:

    set PYTHONUTF8=1
    set AWS_EC2_METADATA_DISABLED=true
    <Attestix>\.venv\Scripts\python.exe \
        <attestix-js>\tests\vectors\generate_vectors.py <attestix-js>\tests\vectors

This emits JSON fixtures that the JS verifier (vitest) loads to prove
byte-for-byte parity (issue VibeTensor/attestix#7). The signing uses the exact
v0.3.0 routines: `auth.crypto.sign_json_payload` (canonicalize_json + Ed25519 +
base64url) for credentials, and `jwt.encode(algorithm="EdDSA")` for delegation
JWTs, matching `CredentialService.issue_credential` /
`DelegationService.create_delegation` field-for-field.
"""

import json
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone

import jwt

from auth.crypto import (
    canonicalize_json,
    did_key_fragment,
    generate_ed25519_keypair,
    public_key_to_bytes,
    private_key_to_bytes,
    public_key_to_did_key,
    sign_json_payload,
)

VC_CONTEXT = [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
]
MUTABLE_FIELDS = {"proof", "credentialStatus"}


def build_credential(server_priv, server_did, subject_id, ctype, issuer_name, claims):
    """Mirror CredentialService.issue_credential exactly (minus storage/audit)."""
    cred_id = f"urn:uuid:{uuid.uuid4()}"
    now = datetime(2026, 5, 27, 12, 0, 0, tzinfo=timezone.utc)
    expires = now + timedelta(days=365)
    credential = {
        "@context": VC_CONTEXT,
        "id": cred_id,
        "type": ["VerifiableCredential", ctype],
        "issuer": {"id": server_did, "name": issuer_name},
        "issuanceDate": now.isoformat(),
        "expirationDate": expires.isoformat(),
        "credentialSubject": {"id": subject_id, **claims},
        "credentialStatus": {
            "id": f"{cred_id}#status",
            "type": "RevocationList2021Status",
            "revoked": False,
            "revocation_reason": None,
            "revoked_at": None,
        },
    }
    proof_payload = {k: v for k, v in credential.items() if k not in MUTABLE_FIELDS}
    signature = sign_json_payload(server_priv, proof_payload)
    credential["proof"] = {
        "type": "Ed25519Signature2020",
        "created": now.isoformat(),
        "verificationMethod": f"{server_did}{did_key_fragment(server_did)}",
        "proofPurpose": "assertionMethod",
        "proofValue": signature,
    }
    return credential


def build_delegation(server_priv, server_did, issuer_agent, audience_agent,
                     capabilities, parent_token=None, expiry_hours=24):
    """Mirror DelegationService.create_delegation token construction exactly."""
    now = int(time.time())
    exp = now + (expiry_hours * 3600)
    jti = f"jti-{uuid.uuid4().hex[:16]}"
    payload = {
        "iss": server_did,
        "aud": audience_agent,
        "sub": audience_agent,
        "iat": now,
        "exp": exp,
        "nbf": now,
        "jti": jti,
        "att": capabilities,
        "delegator": issuer_agent,
        "prf": [parent_token] if parent_token else [],
        "attestix_version": "0.1.0",
        "typ": "ucan/delegation",
    }
    token = jwt.encode(
        payload,
        server_priv,
        algorithm="EdDSA",
        headers={"typ": "JWT", "ucv": "0.9.0", "alg": "EdDSA"},
    )
    return token, payload


def main(out_dir):
    import os
    os.makedirs(out_dir, exist_ok=True)

    # --- Server (root) signing identity ---
    server_priv, server_pub = generate_ed25519_keypair()
    server_did = public_key_to_did_key(server_pub)

    # Agent DIDs (subjects / delegation parties)
    root_priv, root_pub = generate_ed25519_keypair()
    root_did = public_key_to_did_key(root_pub)
    coord_priv, coord_pub = generate_ed25519_keypair()
    coord_did = public_key_to_did_key(coord_pub)
    researcher_priv, researcher_pub = generate_ed25519_keypair()
    researcher_did = public_key_to_did_key(researcher_pub)

    # --- Key material fixture (public only + did) ---
    keys = {
        "server_did": server_did,
        "server_public_key_hex": public_key_to_bytes(server_pub).hex(),
        "root_did": root_did,
        "coordinator_did": coord_did,
        "researcher_did": researcher_did,
    }
    with open(os.path.join(out_dir, "keys.json"), "w", encoding="utf-8") as f:
        json.dump(keys, f, indent=2)

    # --- Verifiable Credential (with non-ASCII claim to exercise UTF-8/NFC) ---
    vc = build_credential(
        server_priv, server_did,
        subject_id=researcher_did,
        ctype="EUAIActComplianceCredential",
        issuer_name="VibeTensor Notified Body",
        claims={
            "article": "Article 43",
            "riskTier": "high",
            "score": 95,
            "passed": True,
            "assessor": "Café Bengio résumé 日本語",  # non-ASCII / NFC test
            "nested": {"z": 1, "a": 2, "m": [3, 2, 1]},
        },
    )
    with open(os.path.join(out_dir, "credential.json"), "w", encoding="utf-8") as f:
        json.dump(vc, f, indent=2, ensure_ascii=False)

    # --- 3-link delegation chain: root -> coordinator -> researcher ---
    # Root grants a broad capability set.
    root_token, root_payload = build_delegation(
        server_priv, server_did,
        issuer_agent=root_did,
        audience_agent=coord_did,
        capabilities=["task:read", "task:write", "task:delegate", "model:invoke"],
    )
    # Coordinator attenuates (drops task:delegate) when delegating to researcher.
    coord_token, coord_payload = build_delegation(
        server_priv, server_did,
        issuer_agent=coord_did,
        audience_agent=researcher_did,
        capabilities=["task:read", "task:write", "model:invoke"],
        parent_token=root_token,
    )
    # Researcher further attenuates to read-only for a sub-task.
    leaf_token, leaf_payload = build_delegation(
        server_priv, server_did,
        issuer_agent=researcher_did,
        audience_agent=researcher_did,
        capabilities=["task:read"],
        parent_token=coord_token,
    )

    delegation = {
        "server_did": server_did,
        "leaf_token": leaf_token,
        "chain_leaf_to_root": [leaf_token, coord_token, root_token],
        "tokens": {
            "root": root_token,
            "coordinator": coord_token,
            "leaf": leaf_token,
        },
        "expected": {
            "leaf_capabilities": ["task:read"],
            "coordinator_capabilities": ["task:read", "task:write", "model:invoke"],
            "root_capabilities": ["task:read", "task:write", "task:delegate", "model:invoke"],
        },
    }
    with open(os.path.join(out_dir, "delegation.json"), "w", encoding="utf-8") as f:
        json.dump(delegation, f, indent=2)

    # --- An ESCALATING (invalid) chain: child requests cap parent never had ---
    bad_root_token, _ = build_delegation(
        server_priv, server_did,
        issuer_agent=root_did,
        audience_agent=coord_did,
        capabilities=["task:read"],
    )
    # Child claims task:admin which the parent never granted (escalation).
    bad_child_token, _ = build_delegation(
        server_priv, server_did,
        issuer_agent=coord_did,
        audience_agent=researcher_did,
        capabilities=["task:read", "task:admin"],
        parent_token=bad_root_token,
    )
    with open(os.path.join(out_dir, "delegation_escalation.json"), "w", encoding="utf-8") as f:
        json.dump({
            "server_did": server_did,
            "leaf_token": bad_child_token,
            "chain_leaf_to_root": [bad_child_token, bad_root_token],
            "note": "child requests task:admin not held by parent -> must be rejected",
        }, f, indent=2)

    # --- Pure JCS parity vectors: object -> exact canonical bytes (hex) ---
    jcs_cases = [
        {"b": 1, "a": 2, "A": 3, "Z": 4, "z": 5},
        {"unicode": "café", "emoji": "rocket", "cjk": "日本語", "nfc": "é"},
        {"nested": {"z": [3, 2, 1], "a": {"inner": True}}, "n": None},
        {"numbers": [1, 1.0, 1.5, 0, 100000000000], "flag": False},
        {"escapes": 'tab\there\nnewline"quote\\backslash\r', "ctrl": ""},
        {"@context": VC_CONTEXT, "type": ["VerifiableCredential", "X"]},
    ]
    jcs_vectors = []
    for case in jcs_cases:
        cb = canonicalize_json(case)
        jcs_vectors.append({
            "input": case,
            "canonical_hex": cb.hex(),
            "canonical_utf8": cb.decode("utf-8"),
        })
    with open(os.path.join(out_dir, "jcs.json"), "w", encoding="utf-8") as f:
        json.dump(jcs_vectors, f, indent=2, ensure_ascii=False)

    print(f"Wrote vectors to {out_dir}")
    print(f"server_did = {server_did}")


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    main(out)
