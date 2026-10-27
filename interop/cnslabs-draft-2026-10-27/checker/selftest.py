"""Synthetic self-test (no packet vectors): builds its own baseline from SPEC/CASES prose."""

import hashlib
import json

import ed25519_strict as ed
import nacl.signing
import rfc8785
import x402acc as X
from eth_keys import keys as ek

T0 = 1791500000
# JCS vs library
for o in [
    {"b": 1, "a": 'é \x01"\\', "c": [1, {"z": 0, "y": "x"}]},
    {"\U0001f600": 1, "￿": 2},
]:
    assert X.jcs_bytes(o) == rfc8785.dumps(o), o
# ed25519 vs nacl
sk = nacl.signing.SigningKey(b"\x01" * 32)
pub = bytes(sk.verify_key)
sig = sk.sign(b"hello").signature
assert ed.verify(pub, b"hello", sig) and not ed.verify(pub, b"hellp", sig)
assert not ed.key_ok(b"\x01" + b"\x00" * 31)  # identity

ks = nacl.signing.SigningKey(b"\x02" * 32)
kb = nacl.signing.SigningKey(b"\x03" * 32)
buyer = ek.PrivateKey(b"\x11" * 32)
baddr = buyer.public_key.to_address().lower()
PAYEE, ASSET = "0x" + "ab" * 20, "0x" + "cd" * 20
rb = {
    "scheme": "x402ev/1",
    "canonicalization": "RFC8785",
    "payment": {
        "network": "eip155:84532",
        "payer": baddr,
        "payee": PAYEE,
        "amount": "10000",
        "asset": ASSET,
    },
    "request": {
        "method": "GET",
        "urlHash": "sha256:" + "00" * 32,
        "clientNonce": "n1",
        "timestamp": T0 - 1,
    },
    "delivery": {
        "statusCode": 200,
        "contentDigest": "sha256:" + "11" * 32,
        "contentType": "a/b",
        "latencyMs": 42,
        "timestamp": T0,
    },
    "signer": {"keyType": "Ed25519", "publicKey": X.b64u_enc(bytes(ks.verify_key))},
}
ref = "x402ev/1:sha256:" + hashlib.sha256(X.jcs_bytes(rb)).hexdigest()
info = dict(rb)
info["evidenceRef"] = ref
info["signer"] = dict(
    rb["signer"],
    signature="base64url:" + X.b64u_enc(ks.sign(X.jcs_bytes(rb)).signature),
)
subject = json.dumps(info).encode()
offer_p = {
    "version": 1,
    "resourceUrl": "https://s/r",
    "scheme": "exact",
    "network": "eip155:84532",
    "asset": ASSET,
    "payTo": PAYEE,
    "amount": "10000",
    "validUntil": T0 + 3600,
}
h = X.b64u_enc(
    json.dumps({"alg": "EdDSA", "kid": "did:web:seller.example#ks"}).encode()
)
p = X.b64u_enc(X.jcs_bytes(offer_p))
offer = json.dumps(
    {
        "format": "jws",
        "signature": h
        + "."
        + p
        + "."
        + X.b64u_enc(ks.sign((h + "." + p).encode()).signature),
    }
).encode()
TA = "0x" + hashlib.sha256(X.jcs_bytes(offer_p)).hexdigest()
body = {
    "version": 0,
    "contextId": "0x" + ref[-64:],
    "deliveryIssuer": "did:web:seller.example",
    "confirmingParty": "eip155:84532:" + baddr,
    "signer": "eip155:84532:" + baddr,
    "authority": {"mode": "direct", "profile": "payer/0", "reference": ""},
    "termsDigest": TA,
    "outcomeDigest": "0x" + "11" * 32,
    "subject": {"profile": "x402ev/1", "reference": ref},
    "disposition": "accepted",
    "issuedAt": T0 + 600,
}
dg = X.acceptance_digest(body, 84532, baddr[2:])
s = buyer.sign_msg_hash(dg)
sig65 = (
    "0x" + (s.r.to_bytes(32, "big") + s.s.to_bytes(32, "big") + bytes([s.v + 27])).hex()
)
trust = {
    "issuers": [
        {
            "issuer": "did:web:seller.example",
            "keys": [{"ed25519": X.b64u_enc(bytes(ks.verify_key))}],
        }
    ],
    "keys": [],
    "authority": [],
}
inp = {
    "record": json.dumps(
        {"format": "eip712", "payload": body, "signature": sig65}
    ).encode(),
    "subject": subject,
    "terms": [offer],
    "trust": trust,
    "chain": [{"chainId": 84532, "account": baddr, "code": False}],
}
r = X.verify(inp)
print(r)
assert r["result"] == "verified", r
# JWS form
jb = dict(
    body,
    confirmingParty="did:example:buyer",
    signer="did:example:buyer",
    authority={"mode": "declared", "profile": "declared-evidence/0", "reference": ""},
)
hh = X.b64u_enc(
    json.dumps({"alg": "EdDSA", "kid": "cp-1", "typ": "x402-acceptance+jws"}).encode()
)
pp = X.b64u_enc(X.jcs_bytes(jb))
jr = hh + "." + pp + "." + X.b64u_enc(kb.sign((hh + "." + pp).encode()).signature)
trust2 = dict(
    trust,
    keys=[
        {
            "kid": "cp-1",
            "signer": "did:example:buyer",
            "key": X.b64u_enc(bytes(kb.verify_key)),
        }
    ],
    authority=[
        {
            "confirmingParty": "did:example:buyer",
            "signer": "did:example:buyer",
            "subjectProfile": "x402ev/1",
            "subjectReference": ref,
        }
    ],
)
r = X.verify(
    dict(
        inp,
        record=json.dumps({"format": "jws", "signature": jr}).encode(),
        trust=trust2,
        chain=[],
    )
)
print(r)
assert r["result"] == "verified", r
print("selftest ok")
