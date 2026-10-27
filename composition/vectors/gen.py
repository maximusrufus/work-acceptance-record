"""Deterministic generator for the composition vectors (C01..C16).

Keys are throwaway: each private key is SHA-256 of a published seed string; never trust a record signed by one.
Ed25519 signing (RFC 8032) is deterministic, and every file is written as sorted, indented JSON with LF endings,
so a rerun reproduces identical bytes. Expected outputs below are written by hand from the two specifications,
not read back from check.py.

CNSLabs signing implemented here from their SPEC.md (tag draft-2026-10-27): the JWS form only (AR-15 header,
AR-16 JCS payload, AR-17 Ed25519 over `protected.payload`). No EIP-712 record is produced.
"""

import base64
import calendar
import copy
import hashlib
import json
import os
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from common import (
    b64url,
    jcs_bytes,
    sha256_hex,
    statement_id,
    war_identity,
)

SPEC_THEIRS = "CNSLabs x402 acceptance record, tag draft-2026-10-27 (commit 428fa21)"
SPEC_OURS = (
    "work-acceptance record, schema trilatic.acceptance-receipt/1.2, profile 1.4.1"
)


def key(seed):
    sk = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed.encode()).digest())
    pk = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return sk, pk


KC = key("composition-vectors/checker")  # work-record checker (subject issuer)
KB = key("composition-vectors/buyer")  # confirming party's JWS key
KP = key("composition-vectors/payer")  # payer-signed variant
KX = key("composition-vectors/unlisted")  # a checker key no relying party lists

ISSUER = "did:web:checker.example"
BUYER = "did:web:buyer.example"
PAYER = "eip155:84532:0xab12ab12ab12ab12ab12ab12ab12ab12ab12ab12"
DELIVERED = b"%PDF-1.7 delivered file\n"
CRITERIA = b'{"criteria_set":"example-criteria","version":"1"}'


def work_record(sk_pk, kid="ck-1", **over):
    body = {
        "canonicalization": "JCS-RFC8785",
        "client_ref": "composition vector",
        "criteria": {
            "commitment": "rfc3161",
            "committed_at": "2026-03-01T00:00:00Z",
            "id": "example-criteria",
            "sha256": sha256_hex(CRITERIA),
            "version": "1",
        },
        "files": {
            "original": {
                "bytes": 20,
                "name": "original.pdf",
                "pages": 1,
                "sha256": "0" * 64,
            },
            "remediated": {
                "bytes": len(DELIVERED),
                "name": "delivered.pdf",
                "pages": 1,
                "sha256": sha256_hex(DELIVERED),
            },
        },
        "human_review": {"scope": ["Example review scope"], "status": "pending"},
        "independence": "independent",
        "issued_utc": "2026-06-01T12:00:00Z",
        "issuer": "Example Checker",
        "key_id": kid,
        "notice": "Test vector. Not a real check.",
        "parties": {
            "checker": {"key_id": kid, "name": "Example Checker"},
            "producer": {"key_id": None, "name": "Example Vendor"},
        },
        "payment": {
            "protocol": "x402",
            "scheme": "exact",
            "network": "eip155:84532",
            "asset": "0x036cbd53842c5426634e7929541ec2318f3dcf7e",
            "payer": "0xAB12ab12AB12ab12AB12ab12AB12ab12AB12ab12",
            "pay_to": "0x2222222222222222222222222222222222222222",
            "amount": "10000",
            "nonce": "0x" + "11" * 32,
        },
        "receipt_id": "EX-C-0001",
        "results": [
            {
                "finding": "Met.",
                "id": "c1",
                "required": True,
                "result": "pass",
                "title": "First criterion",
            }
        ],
        "revision": 1,
        "schema": "trilatic.acceptance-receipt/1.2",
        "suite": {"digest": "sha-256", "signature": "Ed25519"},
        "tools": {"validator": "example 1.0"},
        "verdict": "pass",
    }
    body.update(over)
    sig = sk_pk[0].sign(jcs_bytes(body))
    env = {
        "receipt": body,
        "signature": {
            "alg": "Ed25519",
            "key_id": kid,
            "value": base64.b64encode(sig).decode("ascii"),
        },
        "timestamp": {"status": "none", "reason": "composition vector"},
    }
    return env


def utc(s):
    return calendar.timegm(__import__("time").strptime(s[:19], "%Y-%m-%dT%H:%M:%S"))


def acceptance_body(w_env, **over):
    r = w_env["receipt"]
    ident = war_identity(r)
    body = {
        "version": 0,
        "contextId": "0x" + ident[-64:],
        "deliveryIssuer": ISSUER,
        "confirmingParty": BUYER,
        "signer": BUYER,
        "authority": {
            "mode": "declared",
            "profile": "declared-evidence/0",
            "reference": "",
        },
        "termsDigest": "0x" + r["criteria"]["sha256"],
        "outcomeDigest": "0x" + r["files"]["remediated"]["sha256"],
        "subject": {"profile": "war/1.2", "reference": ident},
        "disposition": "accepted",
        "issuedAt": utc(r["issued_utc"]) + 3600,
    }
    body.update(over)
    return body


def jws(body, sk_pk, kid="cp-1", payload_override=None):
    hdr = b64url(jcs_bytes({"alg": "EdDSA", "kid": kid, "typ": "x402-acceptance+jws"}))
    pl = b64url(jcs_bytes(body))
    sig = sk_pk[0].sign((hdr + "." + pl).encode("ascii"))
    if payload_override is not None:
        pl = b64url(jcs_bytes(payload_override))
    return jcs_bytes({"format": "jws", "signature": hdr + "." + pl + "." + b64url(sig)})


def trust(issuer_keys=((KC, "ck-1"),), keys=((KB, "cp-1", BUYER),), authority=None):
    return {
        "issuers": [
            {
                "issuer": ISSUER,
                "keys": [
                    {"ed25519": b64url(k[1]), "kid": kid} for k, kid in issuer_keys
                ],
            }
        ],
        "keys": [{"kid": kid, "signer": s, "key": b64url(k[1])} for k, kid, s in keys],
        "authority": authority if authority is not None else [],
    }


def declared(body):
    return [
        {
            "confirmingParty": body["confirmingParty"],
            "signer": body["signer"],
            "subjectProfile": body["subject"]["profile"],
            "subjectReference": body["subject"]["reference"],
        }
    ]


def vec(vid, title, note, record, subject_env, tr, expect, body=None):
    return {
        "id": vid,
        "title": title,
        "note": note,
        "specifications": {
            "acceptance": SPEC_THEIRS,
            "work": SPEC_OURS,
            "composition": "war/1.2 subject profile",
        },
        "inputs": {
            "record": b64url(record),
            "subject": b64url(jcs_bytes(subject_env)) if subject_env else None,
            "terms": [],
            "trust": tr,
        },
        "expect": expect,
        "statementId": statement_id(body) if body else None,
        "subjectIdentity": war_identity(subject_env["receipt"])
        if subject_env
        else None,
        "license": "CC0-1.0",
    }


def ok(disp="accepted"):
    return {"result": "verified", "conditions": [], "disposition": disp}


def main():
    W1 = work_record(KC)
    W2 = work_record(KC, receipt_id="EX-C-0002")  # valid, same file and criteria
    W3 = work_record(KC, issued_utc="2026-06-01T12:00:00.500Z")  # fractional issue time
    t1 = utc(W1["receipt"]["issued_utc"])
    out = []

    b = acceptance_body(W1)
    out.append(
        vec(
            "C01-valid-declared",
            "Valid pair, declared-evidence authority",
            "Acceptance names W1 under war/1.2; W1 authenticates under the listed checker key.",
            jws(b, KB),
            W1,
            trust(authority=declared(b)),
            ok(),
            b,
        )
    )

    b = acceptance_body(
        W1,
        confirmingParty=PAYER,
        signer=PAYER,
        authority={"mode": "direct", "profile": "payer/0", "reference": ""},
    )
    out.append(
        vec(
            "C02-valid-payer",
            "Valid pair, payer/0 authority from the work record's payment member",
            "payment.payer is mixed case; the derived payer is lowercased.",
            jws(b, KP, kid="payer-1"),
            W1,
            trust(keys=((KP, "payer-1", PAYER),)),
            ok(),
            b,
        )
    )

    ident = war_identity(W1["receipt"])
    wrong = ident[:-1] + ("0" if ident[-1] != "0" else "1")
    b = acceptance_body(
        W1,
        subject={"profile": "war/1.2", "reference": wrong},
        contextId="0x" + wrong[-64:],
    )
    out.append(
        vec(
            "C03-digest-mismatch",
            "Subject reference does not match the work record digest",
            "subject.reference and contextId carry a digest one hex digit off from sha256(JCS(receipt)).",
            jws(b, KB),
            W1,
            trust(authority=declared(b)),
            {
                "result": "malformed",
                "conditions": ["acceptance_record_digest_mismatch"],
            },
            b,
        )
    )

    b = acceptance_body(
        W1, subject={"profile": "war/9", "reference": "war/9:sha256:" + ident[-64:]}
    )
    out.append(
        vec(
            "C04-unsupported-profile",
            "Unsupported subject profile",
            "subject.profile war/9 is not one this verifier supports.",
            jws(b, KB),
            W1,
            trust(authority=declared(b)),
            {
                "result": "unknown",
                "conditions": [],
                "reason": "profile_unavailable",
                "disposition": "accepted",
            },
            b,
        )
    )

    b = acceptance_body(
        W1,
        subject={"profile": "x402ev/1", "reference": "x402ev/1:sha256:" + ident[-64:]},
    )
    out.append(
        vec(
            "C05-wrong-profile",
            "Wrong profile id for a work record",
            "A work record named under x402ev/1. This checker does not implement x402ev/1, so the profile "
            "is unavailable; a verifier that implements x402ev/1 reports evidence_unavailable, because a "
            "work record does not authenticate as execution evidence.",
            jws(b, KB),
            W1,
            trust(authority=declared(b)),
            {
                "result": "unknown",
                "conditions": [],
                "reason": "profile_unavailable",
                "disposition": "accepted",
            },
            b,
        )
    )

    T = copy.deepcopy(W1)
    T["receipt"]["results"][0]["finding"] = "Met, edited after signing."
    b = acceptance_body(W1)
    out.append(
        vec(
            "C06-tampered-work-record",
            "Work record edited after signing",
            "The supplied work record's signature no longer verifies, so the subject is unavailable.",
            jws(b, KB),
            T,
            trust(authority=declared(b)),
            {
                "result": "unknown",
                "conditions": [],
                "reason": "evidence_unavailable",
                "disposition": "accepted",
            },
            b,
        )
    )

    b = acceptance_body(W1)
    b_t = dict(b, disposition="rejected")
    out.append(
        vec(
            "C07-tampered-acceptance",
            "Acceptance record edited after signing",
            "The JWS payload is replaced by JCS of the body with disposition rejected; signature kept.",
            jws(b, KB, payload_override=b_t),
            W1,
            trust(authority=declared(b)),
            {"result": "malformed", "conditions": ["signature_invalid"]},
            b_t,
        )
    )

    b = acceptance_body(W1)
    out.append(
        vec(
            "C08-valid-but-unbound",
            "Both records valid, not bound to each other",
            "The acceptance names W1; the supplied subject is W2, a different valid record from the same "
            "checker on the same file and criteria.",
            jws(b, KB),
            W2,
            trust(authority=declared(b)),
            {
                "result": "malformed",
                "conditions": ["acceptance_record_digest_mismatch"],
            },
            b,
        )
    )

    b = acceptance_body(W1, outcomeDigest="0x" + sha256_hex(b"other bytes"))
    out.append(
        vec(
            "C09-outcome-mismatch",
            "outcomeDigest differs from files.remediated.sha256",
            "",
            jws(b, KB),
            W1,
            trust(authority=declared(b)),
            {
                "result": "malformed",
                "conditions": ["acceptance_outcome_digest_mismatch"],
            },
            b,
        )
    )

    b = acceptance_body(W1, termsDigest="0x" + sha256_hex(b"other criteria"))
    out.append(
        vec(
            "C10-terms-mismatch",
            "termsDigest differs from criteria.sha256",
            "",
            jws(b, KB),
            W1,
            trust(authority=declared(b)),
            {"result": "malformed", "conditions": ["acceptance_terms_digest_mismatch"]},
            b,
        )
    )

    b = acceptance_body(W3, issuedAt=t1)
    out.append(
        vec(
            "C11-precedes-fractional",
            "issuedAt before a fractional issued_utc",
            "issued_utc 12:00:00.500Z rounds up to t+1; issuedAt is t.",
            jws(b, KB),
            W3,
            trust(authority=declared(b)),
            {"result": "malformed", "conditions": ["acceptance_precedes_outcome"]},
            b,
        )
    )

    b = acceptance_body(W3, issuedAt=t1 + 1)
    out.append(
        vec(
            "C12-equal-boundary",
            "issuedAt equal to the rounded-up issued_utc",
            "Equal values are allowed (AR-26).",
            jws(b, KB),
            W3,
            trust(authority=declared(b)),
            ok(),
            b,
        )
    )

    b = acceptance_body(W1, confirmingParty=BUYER, signer="checker-signer")
    out.append(
        vec(
            "C13-signer-is-issuer",
            "Acceptance signed with the work record's checker key",
            "trust.keys maps the checker key to another signer string; AR-33 still fires on the key.",
            jws(b, KC, kid="ck-as-cp"),
            W1,
            trust(keys=((KC, "ck-as-cp", "checker-signer"),), authority=declared(b)),
            {"result": "malformed", "conditions": ["acceptance_signer_is_issuer"]},
            b,
        )
    )

    WX = work_record(KX, kid="ck-x")
    b = acceptance_body(WX)
    out.append(
        vec(
            "C14-checker-key-unlisted",
            "Work record signed by a key the relying party does not list",
            "",
            jws(b, KB),
            WX,
            trust(authority=declared(b)),
            {
                "result": "unknown",
                "conditions": [],
                "reason": "evidence_unavailable",
                "disposition": "accepted",
            },
            b,
        )
    )

    b = acceptance_body(W1)
    out.append(
        vec(
            "C15-subject-absent",
            "Work record not supplied",
            "",
            jws(b, KB),
            None,
            trust(authority=declared(b)),
            {
                "result": "unknown",
                "conditions": [],
                "reason": "evidence_unavailable",
                "disposition": "accepted",
            },
            b,
        )
    )

    b = acceptance_body(W1)
    out.append(
        vec(
            "C16-authority-other-record",
            "Declared authority names a different work record",
            "The trust.authority entry's subjectReference is W2's identity.",
            jws(b, KB),
            W1,
            trust(
                authority=[
                    dict(declared(b)[0], subjectReference=war_identity(W2["receipt"]))
                ]
            ),
            {
                "result": "unknown",
                "conditions": ["acceptance_authority_unresolved"],
                "disposition": "accepted",
            },
            b,
        )
    )

    for v in out:
        with open(
            os.path.join(HERE, v["id"] + ".json"), "w", encoding="utf-8", newline="\n"
        ) as f:
            f.write(json.dumps(v, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    print(f"wrote {len(out)} vectors")


if __name__ == "__main__":
    main()
