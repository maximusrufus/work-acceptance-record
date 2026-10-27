"""Phase 3: mutate valid vectors; run the FROZEN checker (imported from checker/, unchanged)."""

import copy
import hashlib
import hmac
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "checker"))
import nacl.signing
import run_vectors as RV
import x402acc as X
from eth_keys import keys as ek

vec = {v["id"]: v for v in json.load(open(os.path.join(ROOT, "sealed", "vectors.json")))["vectors"]}
seeds = {
    k: bytes.fromhex(v.removeprefix("0x"))
    for k, v in json.load(open(os.path.join(ROOT, "sealed", "seeds.json")))["seeds"].items()
}
ED = {k: nacl.signing.SigningKey(seeds[k]) for k in ("ks", "kb")}
ETH = {k: ek.PrivateKey(seeds[k]) for k in ("buyer", "other")}
N = X.N
D = lambda s: X.b64u_dec(s)
E = X.b64u_enc


def base(vid):
    v = copy.deepcopy(vec[vid])
    i = v["inputs"]
    env = json.loads(D(i["record"]))
    pay = env["payload"] if "payload" in env else json.loads(D(env["signature"].split(".")[1]))
    return i, pay, D(i["subject"]), [D(t) for t in i["terms"]]


def sign712(body, who="buyer", chain=84532, acct=None, domain_chain=False):
    key = ETH[who]
    a = acct or key.public_key.to_address()[2:].lower()
    dg = X.acceptance_digest(body, chain, a)
    s = key.sign_msg_hash(dg)
    return (
        "0x"
        + (s.r.to_bytes(32, "big") + s.s.to_bytes(32, "big") + bytes([s.v + 27])).hex()
    )


def env712(body, sig):
    return json.dumps({"format": "eip712", "payload": body, "signature": sig}).encode()


def jws(body, hdr=None, key="kb", payload=None):
    hdr = hdr or {"alg": "EdDSA", "kid": "cp-1", "typ": "x402-acceptance+jws"}
    h = E(json.dumps(hdr, separators=(",", ":")).encode())
    p = E(payload if payload is not None else X.jcs_bytes(body))
    sg = ED[key].sign((h + "." + p).encode()).signature
    return h, p, sg


def jws_env(h, p, sg):
    return json.dumps(
        {"format": "jws", "signature": h + "." + p + "." + E(sg)}
    ).encode()


def mk(i, record=None, subject=None, terms=None, **kw):
    j = copy.deepcopy(i)
    if record is not None:
        j["record"] = E(record)
    if subject is not None:
        j["subject"] = E(subject)
    if terms is not None:
        j["terms"] = [E(t) for t in terms]
    for k, v in kw.items():
        j[k] = v
    return j


def resign_receipt(raw, change):
    info = json.loads(raw)
    change(info)
    body = {k: v for k, v in info.items() if k not in ("evidenceRef", "transparency")}
    body["signer"] = {k: v for k, v in info["signer"].items() if k != "signature"}
    info["evidenceRef"] = (
        "x402ev/1:sha256:" + hashlib.sha256(X.jcs_bytes(body)).hexdigest()
    )
    info["signer"]["signature"] = "base64url:" + E(
        ED["ks"].sign(X.jcs_bytes(body)).signature
    )
    return json.dumps(info).encode()


def resign_offer(raw, change):
    env = json.loads(raw)
    h, p, _ = env["signature"].split(".")
    pl = json.loads(D(p))
    change(pl)
    p2 = E(X.jcs_bytes(pl))
    sg = ED["ks"].sign((h + "." + p2).encode()).signature
    return json.dumps(
        {"format": "jws", "signature": h + "." + p2 + "." + E(sg)}
    ).encode()


M = []  # (name, inputs, expected result, expected conditions, reason)


def add(name, inp, res, conds=(), reason=None, extra=None):
    M.append((name, inp, res, set(conds), reason, extra))


# ---------- sanity: re-signing reproduces verified
ie, be, se, te = base("AR-C01-a-eip712")
add("S0 resign eip712 unchanged", mk(ie, env712(be, sign712(be))), "verified")
ij, bj, sj, tj = base("AR-C01-a-jws")
add("S1 resign jws unchanged", mk(ij, jws_env(*jws(bj))), "verified")

# ---------- EIP-712 mutations
b = dict(be, disposition="rejected")
add(
    "E1 field change, old sig",
    mk(ie, env712(b, json.loads(D(ie["record"]))["signature"])),
    "malformed",
    ["signature_invalid"],
)
b = dict(be, termsDigest="0x" + "ee" * 32)
add(
    "E2 termsDigest changed, resigned",
    mk(ie, env712(b, sign712(b))),
    "malformed",
    ["acceptance_terms_digest_mismatch"],
)
b = dict(
    be,
    signer=be["signer"].replace("84532", "8453"),
    confirmingParty=be["signer"].replace("84532", "8453"),
)
acct = be["signer"].split(":")[2]
add(
    "E3 wrong chain id, resigned, chain says no code on 8453",
    mk(
        ie,
        env712(b, sign712(b, chain=8453)),
        chain=ie["chain"]
        + [{"chainId": 8453, "block": 1000, "account": acct, "code": False}],
    ),
    "unknown",
    ["acceptance_authority_unresolved"],
    extra="payer string is eip155:84532:..., record names 8453",
)
add(
    "E4 wrong chain id, old sig",
    mk(
        ie,
        env712(b, json.loads(D(ie["record"]))["signature"]),
        chain=ie["chain"]
        + [{"chainId": 8453, "block": 1000, "account": acct, "code": False}],
    ),
    "malformed",
    ["signature_invalid"],
)
add(
    "E5 wrong chain id, no chain facts",
    mk(ie, env712(b, sign712(b, chain=8453))),
    "key_unresolved",
    [],
    "chain_state_unavailable",
)
add(
    "E6 receipt payee swap, unsigned",
    mk(
        ie,
        subject=(lambda r: (r["payment"].__setitem__("payee", "0x" + "99" * 20), json.dumps(r).encode())[1])(json.loads(se)),
    ),
    "unknown",
    [],
    "evidence_unavailable",
)


def swp(r):
    r["payment"]["payee"] = "0x" + "99" * 20


add(
    "E7 receipt payee swap, re-signed by seller, record not updated",
    mk(ie, subject=resign_receipt(se, swp)),
    "malformed",
    ["acceptance_record_digest_mismatch"],
)
sg0 = json.loads(D(ie["record"]))["signature"]
r_, s_, v_ = int(sg0[2:66], 16), int(sg0[66:130], 16), int(sg0[130:], 16)
add(
    "E8 high-s + flipped v",
    mk(ie, env712(be, "0x%064x%064x%02x" % (r_, N - s_, 55 - v_))),
    "malformed",
    ["signature_invalid"],
)
add(
    "E9 v normalized to 0/1",
    mk(ie, env712(be, sg0[:130] + "%02x" % (v_ - 27))),
    "malformed",
    ["signature_invalid"],
)
add(
    "E10 uppercase hex signature",
    mk(ie, env712(be, "0x" + sg0[2:].upper())),
    "malformed",
    ["signature_invalid"],
)
add(
    "E11 signed by OTHER, body names BUYER",
    mk(
        ie,
        env712(
            be,
            sign712(
                be, who="other", acct=ETH["buyer"].public_key.to_address()[2:].lower()
            ),
        ),
    ),
    "malformed",
    ["signature_invalid"],
)
b = dict(be, issuedAt=1791500000 - 1)
add(
    "E12 issuedAt before outcome, resigned",
    mk(ie, env712(b, sign712(b))),
    "malformed",
    ["acceptance_precedes_outcome"],
)


def swo(o):
    o["payTo"] = "0x" + "99" * 20


add(
    "E13 offer payTo swapped (resigned by seller)",
    mk(ie, terms=[resign_offer(te[0], swo)]),
    "unknown",
    [],
    "evidence_unavailable",
)


def exp(o):
    o["validUntil"] = 1791500000 - 1


add(
    "E14 offer expired before outcome",
    mk(ie, terms=[resign_offer(te[0], exp)]),
    "unknown",
    [],
    "evidence_unavailable",
)
b = dict(be, extra="x")
add(
    "E15 extra member, resigned (typed msg unchanged)",
    mk(ie, env712(b, sign712(be))),
    "malformed",
    ["acceptance_member_invalid"],
)
b = dict(
    be,
    signer=be["signer"].replace(
        acct, acct[:-1] + acct[-1].upper() if acct[-1].isalpha() else acct.upper()
    ),
)
add(
    "E16 uppercase signer address",
    mk(ie, env712(b, sign712(be))),
    "malformed",
    ["acceptance_member_invalid"],
)
b = dict(be, confirmingParty="did:web:acme.example")
add(
    "E17 payer signs for another party",
    mk(ie, env712(b, sign712(b))),
    "unknown",
    ["acceptance_authority_unresolved"],
)
add("E18 terms input empty", mk(ie, terms=[]), "unknown", [], "evidence_unavailable")
b = dict(be, deliveryIssuer="did:web:other.example")
add(
    "E19 deliveryIssuer changed to unlisted issuer",
    mk(ie, env712(b, sign712(b))),
    "unknown",
    [],
    "evidence_unavailable",
)
b = (
    dict(be, signer="eip155:84532:" + acct.upper().replace("0X", "0x"))
    if False
    else None
)

# ---------- JWS mutations
b = dict(bj, disposition="rejected")
add(
    "J1 field change, old sig",
    mk(ij, jws_env(*jws(bj)[:2], jws(bj)[2]) if False else None)
    if False
    else mk(ij, (lambda h, p, s: jws_env(h, E(X.jcs_bytes(b)), s))(*jws(bj))),
    "malformed",
    ["signature_invalid"],
)
for alg in ("none", "HS256", "ES256K"):
    hdr = {"alg": alg, "kid": "cp-1", "typ": "x402-acceptance+jws"}
    sg = (
        hmac.new(D(ij["trust"]["keys"][0]["key"]), b"x", hashlib.sha256).digest()
        if alg == "HS256"
        else b""
    )
    h = E(json.dumps(hdr, separators=(",", ":")).encode())
    p = E(X.jcs_bytes(bj))
    add(
        "J2 alg=%s confusion" % alg,
        mk(ij, jws_env(h, p, sg)),
        "malformed",
        ["acceptance_member_invalid"],
    )
pl = json.dumps(bj, separators=(",", ":"), sort_keys=False).encode()
rev = json.dumps(dict(reversed(list(bj.items()))), separators=(",", ":")).encode()
add(
    "J3 non-canonical key order, resigned",
    mk(ij, jws_env(*jws(bj, payload=rev))),
    "malformed",
    ["acceptance_member_invalid"],
)
add(
    "J4 non-canonical whitespace, resigned",
    mk(ij, jws_env(*jws(bj, payload=json.dumps(bj).encode()))),
    "malformed",
    ["acceptance_member_invalid"],
)
add(
    "J5 unknown kid with complete=true",
    mk(
        ij,
        jws_env(
            *jws(bj, hdr={"alg": "EdDSA", "kid": "cp-7", "typ": "x402-acceptance+jws"})
        ),
        trust=dict(ij["trust"], complete=True),
    ),
    "key_unresolved",
    [],
    "key_missing",
)
h, p, sg = jws(bj)
s_int = (
    int.from_bytes(sg[32:], "little") + 2**252 + 27742317777372353535851937790883648493
)
add(
    "J6 S+L malleated signature",
    mk(ij, jws_env(h, p, sg[:32] + (s_int % 2**256).to_bytes(32, "little"))),
    "malformed",
    ["signature_invalid"],
)
add(
    "J7 signed by issuer key KS as cp-1",
    mk(ij, jws_env(*jws(bj, key="ks"))),
    "malformed",
    ["signature_invalid"],
)
t = copy.deepcopy(ij["trust"])
t["keys"][0]["key"] = E(bytes(ED["ks"].verify_key))
add(
    "J8 trust.keys maps cp-1 to issuer key KS",
    mk(ij, jws_env(*jws(bj, key="ks")), trust=t),
    "malformed",
    ["acceptance_signer_is_issuer"],
)
b = dict(bj, disposition="not_responded")
add(
    "J9 not_responded",
    mk(ij, jws_env(*jws(b))),
    "malformed",
    ["acceptance_member_invalid"],
)
b = dict(bj, issuedAt=2**53)
add(
    "J10 issuedAt 2^53",
    mk(ij, jws_env(*jws(b, payload=json.dumps(b, separators=(",", ":")).encode()))),
    "malformed",
    ["acceptance_member_invalid"],
)
b = dict(bj, contextId=bj["contextId"].upper().replace("0X", "0x"))
add(
    "J11 uppercase contextId",
    mk(ij, jws_env(*jws(b))),
    "malformed",
    ["acceptance_member_invalid", "acceptance_record_digest_mismatch"]
    if False
    else ["acceptance_member_invalid"],
)
h, p, sg = jws(bj)
add(
    "J12 padded base64url signature",
    mk(
        ij,
        json.dumps(
            {"format": "jws", "signature": h + "." + p + "." + E(sg) + "=="}
        ).encode(),
    ),
    "malformed",
    ["acceptance_member_invalid"],
)
b = dict(bj, signer="did:example:buyer ", confirmingParty="did:example:buyer ")
add(
    "J13 trailing space in signer (no trimming)",
    mk(ij, jws_env(*jws(b))),
    "key_unresolved",
    [],
    "signer_mismatch",
)
b = dict(bj, version=1)
add(
    "J14 version 1",
    mk(ij, jws_env(*jws(b))),
    "malformed",
    ["acceptance_member_invalid"],
)
b = dict(bj, termsDigest="0x" + "ab" * 32)
add(
    "J15 terms mismatch",
    mk(ij, jws_env(*jws(b))),
    "malformed",
    ["acceptance_terms_digest_mismatch"],
)
t = copy.deepcopy(ij["trust"])
t["authority"] = []
add(
    "J16 declared authority removed",
    mk(ij, trust=t),
    "unknown",
    ["acceptance_authority_unresolved"],
)
t = copy.deepcopy(ij["trust"])
t["issuers"][0]["keys"].append({"ed25519": E(bytes(ED["kb"].verify_key))})
add(
    "J17 buyer key also listed for issuer",
    mk(ij, trust=t),
    "malformed",
    ["acceptance_signer_is_issuer"],
)
add(
    "J18 outcome bytes supplied that do not hash to digest",
    mk(ij, outcome=E(b"other")),
    "malformed",
    ["acceptance_outcome_digest_mismatch"],
)

rows, bad = [], []
for name, inp, res, conds, reason, extra in M:
    got = RV.run_one({"inputs": RV.to_inputs(inp)} if False else {"inputs": inp})
    ok = (
        got["result"] == res
        and set(got["conditions"]) == conds
        and (reason is None or got.get("reason") == reason)
    )
    rows.append((name, ok, got))
    if not ok:
        bad.append((name, got, res, sorted(conds), reason))
print(len(M), "mutations;", sum(1 for r in rows if r[1]), "as spec predicts")
for name, got, res, conds, reason in bad:
    print("DIFF", name, "got", json.dumps(got), "want", res, conds, reason)
json.dump(
    [{"name": n, "ok": o, "got": g} for n, o, g in rows],
    open(os.path.join(ROOT, "results", "phase3.json"), "w"),
    indent=1,
)
