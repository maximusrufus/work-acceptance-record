"""Clean-room verifier for the x402 acceptance record, version 0 (packet/SPEC.md)."""

import base64
import hashlib
import json
import re

import ed25519_strict as ed
from Crypto.Hash import keccak
from eth_keys import keys as ethkeys


class InputRefused(Exception):
    """AR-18: input refused before verify runs (duplicate kid)."""


class Bad(Exception):
    pass


# ---------------------------------------------------------------- helpers
def b64u_dec(s):
    """Strict canonical unpadded base64url -> bytes, or None."""
    if (
        not isinstance(s, str)
        or not re.fullmatch(r"[A-Za-z0-9_-]*", s)
        or len(s) % 4 == 1
    ):
        return None
    try:
        raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except Exception:
        return None
    if base64.urlsafe_b64encode(raw).decode().rstrip("=") != s:
        return None
    return raw


def b64u_enc(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _no_surrogates(v):
    if isinstance(v, str):
        if any(0xD800 <= ord(c) <= 0xDFFF for c in v):
            raise Bad("lone surrogate")
    elif isinstance(v, list):
        for x in v:
            _no_surrogates(x)
    elif isinstance(v, dict):
        for k, x in v.items():
            _no_surrogates(k)
            _no_surrogates(x)


def _pairs(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise Bad("duplicate member")
        d[k] = v
    return d


def _pint(t):
    if t.startswith("-") or t.startswith("+"):
        raise Bad("signed int")
    return int(t)


def _bad(_):
    raise Bad("non-integer number")


def parse_ijson(b):
    """Strict I-JSON (RFC 7493) parse of bytes with integer-only numbers (AR-6)."""
    try:
        txt = b.decode("utf-8") if isinstance(b, (bytes, bytearray)) else b
        v = json.loads(
            txt,
            object_pairs_hook=_pairs,
            parse_float=_bad,
            parse_int=_pint,
            parse_constant=_bad,
        )
        _no_surrogates(v)
        return v
    except Bad:
        raise
    except Exception as e:
        raise Bad(str(e))


def _jstr(s):
    out = ['"']
    for c in s:
        o = ord(c)
        if c == '"':
            out.append('\\"')
        elif c == "\\":
            out.append("\\\\")
        elif c == "\b":
            out.append("\\b")
        elif c == "\t":
            out.append("\\t")
        elif c == "\n":
            out.append("\\n")
        elif c == "\f":
            out.append("\\f")
        elif c == "\r":
            out.append("\\r")
        elif o < 0x20:
            out.append("\\u%04x" % o)
        else:
            out.append(c)
    out.append('"')
    return "".join(out)


def jcs(v):
    """RFC 8785 for values built of objects, arrays, strings, ints, bool, null."""
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        if abs(v) > 2**53:
            raise Bad("int outside JCS exact range")
        return str(v)
    if isinstance(v, str):
        return _jstr(v)
    if isinstance(v, list):
        return "[" + ",".join(jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        ks = sorted(v.keys(), key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(_jstr(k) + ":" + jcs(v[k]) for k in ks) + "}"
    raise Bad("unsupported type")


def jcs_bytes(v):
    return jcs(v).encode("utf-8")


def is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


HEX32 = re.compile(r"0x[0-9a-f]{64}")
ADDR = re.compile(r"0x[0-9a-fA-F]{40}")
SIGNER = re.compile(r"eip155:([1-9][0-9]*):0x([0-9a-f]{40})")
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def keccak256(b):
    return keccak.new(digest_bits=256, data=b).digest()


def _u256(n):
    return n.to_bytes(32, "big")


def _strh(s):
    return keccak256(s.encode("utf-8"))


ACC_T = (
    "Acceptance(uint256 version,bytes32 contextId,string deliveryIssuer,string confirmingParty,"
    "uint256 signerChainId,address signerAccount,Authority authority,bytes32 termsDigest,"
    "bytes32 outcomeDigest,Subject subject,string disposition,uint64 issuedAt)"
)
AUTH_T = "Authority(string mode,string profile,string reference)"
SUBJ_T = "Subject(string profile,string reference)"
ACC_TH = keccak256((ACC_T + AUTH_T + SUBJ_T).encode())
AUTH_TH = keccak256(AUTH_T.encode())
SUBJ_TH = keccak256(SUBJ_T.encode())
DOM_SEP = keccak256(
    keccak256(b"EIP712Domain(string name,string version)")
    + _strh("x402 acceptance")
    + _strh("0")
)


def acceptance_digest(body, chain_id, account_hex):
    a, s = body["authority"], body["subject"]
    ah = keccak256(
        AUTH_TH + _strh(a["mode"]) + _strh(a["profile"]) + _strh(a["reference"])
    )
    sh = keccak256(SUBJ_TH + _strh(s["profile"]) + _strh(s["reference"]))
    enc = (
        ACC_TH
        + _u256(body["version"])
        + bytes.fromhex(body["contextId"][2:])
        + _strh(body["deliveryIssuer"])
        + _strh(body["confirmingParty"])
        + _u256(chain_id)
        + b"\x00" * 12
        + bytes.fromhex(account_hex)
        + ah
        + bytes.fromhex(body["termsDigest"][2:])
        + bytes.fromhex(body["outcomeDigest"][2:])
        + sh
        + _strh(body["disposition"])
        + _u256(body["issuedAt"])
    )
    return keccak256(b"\x19\x01" + DOM_SEP + keccak256(enc))


OFFER_T = (
    "Offer(uint256 version,string resourceUrl,string scheme,string network,string asset,"
    "string payTo,string amount,uint256 validUntil)"
)
OFFER_TH = keccak256(OFFER_T.encode())
OFFER_DOM = keccak256(
    keccak256(b"EIP712Domain(string name,string version,uint256 chainId)")
    + _strh("x402 offer")
    + _strh("1")
    + _u256(1)
)


def offer_digest(p):
    enc = (
        OFFER_TH
        + _u256(p["version"])
        + _strh(p["resourceUrl"])
        + _strh(p["scheme"])
        + _strh(p["network"])
        + _strh(p["asset"])
        + _strh(p["payTo"])
        + _strh(p["amount"])
        + _u256(p.get("validUntil", 0))
    )
    return keccak256(b"\x19\x01" + OFFER_DOM + keccak256(enc))


def recover(digest, sig65, strict):
    """Return lowercase 0x address or None. strict = AR-13 checks."""
    r = int.from_bytes(sig65[:32], "big")
    s = int.from_bytes(sig65[32:64], "big")
    v = sig65[64]
    if strict:
        if v not in (27, 28) or not (0 < r < N) or not (0 < s <= N // 2):
            return None
        yp = v - 27
    else:
        yp = v - 27 if v in (27, 28) else v
        if yp not in (0, 1) or not (0 < r < N) or not (0 < s < N):
            return None
    try:
        sig = ethkeys.Signature(vrs=(yp, r, s))
        return sig.recover_public_key_from_msg_hash(digest).to_address().lower()
    except Exception:
        return None


def addr_eq(a, b):
    if (
        isinstance(a, str)
        and isinstance(b, str)
        and ADDR.fullmatch(a)
        and ADDR.fullmatch(b)
    ):
        return a.lower() == b.lower()
    return a == b


def out(result, conditions=(), **kw):
    d = {"result": result, "conditions": sorted(set(conditions))}
    d.update({k: v for k, v in kw.items() if v is not None})
    return d


# ---------------------------------------------------------------- subject x402ev/1
def issuer_entries(trust, issuer):
    return [
        e
        for e in (trust.get("issuers") or [])
        if isinstance(e, dict) and e.get("issuer") == issuer
    ]


def issuer_ed_keys(trust, issuer):
    ks = []
    for e in issuer_entries(trust, issuer):
        for k in e.get("keys") or []:
            if isinstance(k, dict) and "ed25519" in k:
                kb = b64u_dec(k["ed25519"])
                if kb is not None:
                    ks.append(kb)
    return ks


def issuer_addrs(trust, issuer):
    return [
        k["address"].lower()
        for e in issuer_entries(trust, issuer)
        for k in (e.get("keys") or [])
        if isinstance(k, dict) and isinstance(k.get("address"), str)
    ]


def load_subject(subject_bytes, trust, issuer):
    """Return dict or None (unavailable)."""
    if subject_bytes is None or not isinstance(issuer, str):
        return None
    try:
        info = parse_ijson(subject_bytes)
        if not isinstance(info, dict):
            return None
        sg, pay, dl = info.get("signer"), info.get("payment"), info.get("delivery")
        if not (
            isinstance(sg, dict) and isinstance(pay, dict) and isinstance(dl, dict)
        ):
            return None
        ref = info.get("evidenceRef")
        if not isinstance(ref, str) or sg.get("keyType") != "Ed25519":
            return None
        body = {
            k: v for k, v in info.items() if k not in ("evidenceRef", "transparency")
        }
        body["signer"] = {k: v for k, v in sg.items() if k != "signature"}
        if ref != "x402ev/1:sha256:" + hashlib.sha256(jcs_bytes(body)).hexdigest():
            return None
        pub = b64u_dec(sg.get("publicKey"))
        sigs = sg.get("signature")
        if (
            pub is None
            or len(pub) != 32
            or not isinstance(sigs, str)
            or not sigs.startswith("base64url:")
        ):
            return None
        sig = b64u_dec(sigs[len("base64url:") :])
        if sig is None or pub not in issuer_ed_keys(trust, issuer):
            return None
        if not ed.verify(pub, jcs_bytes(body), sig):
            return None
        payer, payee = pay.get("payer"), pay.get("payee")
        # verification rule 1: payer and payee are distinct non-null entities
        if not (
            isinstance(payer, str)
            and isinstance(payee, str)
            and payer
            and payee
            and not addr_eq(payer, payee)
        ):
            return None
        cd = dl.get("contentDigest")
        if not (isinstance(cd, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", cd)):
            return None
        ts = dl.get("timestamp")
        if not is_int(ts):
            return None
        pr = None
        net = pay.get("network")
        if (
            isinstance(net, str)
            and re.fullmatch(r"eip155:[0-9]+", net)
            and ADDR.fullmatch(payer)
        ):
            pr = net + ":" + payer.lower()
        return dict(ref=ref, outcome="0x" + cd[7:], time=ts, payer=pr, pay=pay, pub=pub)
    except Bad:
        return None


def offer_digests(terms, trust, issuer, subj):
    """AR-29: digests of qualifying offers."""
    res = []
    keys = issuer_ed_keys(trust, issuer)
    addrs = issuer_addrs(trust, issuer)
    pay = subj["pay"]
    for tb in terms or []:
        try:
            env = parse_ijson(tb)
            if not isinstance(env, dict):
                continue
            fmt = env.get("format")
            if fmt == "jws":
                if set(env) != {"format", "signature"} or not isinstance(
                    env["signature"], str
                ):
                    continue
                parts = env["signature"].split(".")
                if len(parts) != 3:
                    continue
                hb, pb, sb = (b64u_dec(x) for x in parts)
                if hb is None or pb is None or sb is None:
                    continue
                hdr = parse_ijson(hb)
                if (
                    not isinstance(hdr, dict)
                    or hdr.get("alg") != "EdDSA"
                    or not isinstance(hdr.get("kid"), str)
                ):
                    continue
                payload = parse_ijson(pb)
                msg = (parts[0] + "." + parts[1]).encode("ascii")
                if not any(ed.verify(k, msg, sb) for k in keys):
                    continue
            elif fmt == "eip712":
                if set(env) != {"format", "payload", "signature"}:
                    continue
                payload, sg = env["payload"], env["signature"]
                if (
                    not isinstance(payload, dict)
                    or not isinstance(sg, str)
                    or not re.fullmatch(r"0x[0-9a-fA-F]{130}", sg)
                ):
                    continue
                if not all(
                    isinstance(payload.get(k), str)
                    for k in (
                        "resourceUrl",
                        "scheme",
                        "network",
                        "asset",
                        "payTo",
                        "amount",
                    )
                ):
                    continue
                if (
                    not is_int(payload.get("version"))
                    or payload["version"] != 1
                    or not is_int(payload.get("validUntil"))
                ):
                    continue
                rec = recover(offer_digest(payload), bytes.fromhex(sg[2:]), False)
                if rec is None or rec not in addrs:
                    continue
            else:
                continue
            if not isinstance(payload, dict) or payload.get("version") != 1:
                continue
            if not all(
                isinstance(payload.get(k), str)
                for k in ("network", "asset", "payTo", "amount")
            ):
                continue
            if payload["network"] != pay.get("network") or payload["amount"] != pay.get(
                "amount"
            ):
                continue
            if not addr_eq(payload["asset"], pay.get("asset")) or not addr_eq(
                payload["payTo"], pay.get("payee")
            ):
                continue
            vu = payload.get("validUntil")
            if vu is not None:
                if not is_int(vu):
                    continue
                if vu != 0 and vu < subj["time"]:
                    continue
            res.append("0x" + hashlib.sha256(jcs_bytes(payload)).hexdigest())
        except Bad:
            continue
    return res


# ---------------------------------------------------------------- verify
KEYS11 = {
    "version",
    "contextId",
    "deliveryIssuer",
    "confirmingParty",
    "signer",
    "authority",
    "termsDigest",
    "outcomeDigest",
    "subject",
    "disposition",
    "issuedAt",
}


def _preflight_eip712(env):
    """Return (body, chainId, accountHex) or None when the typed message cannot be built."""
    if set(env) != {"format", "payload", "signature"} or not isinstance(
        env["signature"], str
    ):
        return None
    body = env["payload"]
    if not isinstance(body, dict):
        return None
    for k in ("contextId", "termsDigest", "outcomeDigest"):
        if not (isinstance(body.get(k), str) and HEX32.fullmatch(body[k])):
            return None
    if not (is_int(body.get("version")) and body["version"] == 0):
        return None
    if not (is_int(body.get("issuedAt")) and 0 <= body["issuedAt"] <= 2**53 - 1):
        return None
    for k in ("deliveryIssuer", "confirmingParty", "disposition"):
        if not isinstance(body.get(k), str):
            return None
    for k, ks in (
        ("authority", ("mode", "profile", "reference")),
        ("subject", ("profile", "reference")),
    ):
        o = body.get(k)
        if not isinstance(o, dict) or not all(isinstance(o.get(x), str) for x in ks):
            return None
    sgn = body.get("signer")
    m = SIGNER.fullmatch(sgn) if isinstance(sgn, str) else None
    if not m or int(m.group(1)) > 2**256 - 1 or int(m.group(2), 16) == 0:
        return None
    return body, int(m.group(1)), m.group(2)


def verify(inp):
    rec = inp.get("record")
    trust = inp.get("trust") or {}
    if rec is None:
        return out("no_record")
    kids = [k.get("kid") for k in (trust.get("keys") or []) if isinstance(k, dict)]
    if len(kids) != len(set(kids)):
        raise InputRefused("duplicate kid in trust.keys")

    def MI():
        return out("malformed", ["acceptance_member_invalid"])

    # ---- step 2 preflight
    try:
        env = parse_ijson(rec)
    except Bad:
        return MI()
    if not isinstance(env, dict):
        return MI()
    fmt = env.get("format")
    jws = None
    if fmt == "eip712":
        pf = _preflight_eip712(env)
        if pf is None:
            return MI()
        body, cid, acct = pf
    elif fmt == "jws":
        if set(env) != {"format", "signature"} or not isinstance(env["signature"], str):
            return MI()
        parts = env["signature"].split(".")
        if len(parts) != 3:
            return MI()
        hb, pb, sb = (b64u_dec(x) for x in parts)
        if hb is None or pb is None or sb is None:
            return MI()
        try:
            hdr = parse_ijson(hb)
            body = parse_ijson(pb)
        except Bad:
            return MI()
        if not (
            isinstance(hdr, dict)
            and set(hdr) == {"alg", "kid", "typ"}
            and hdr["alg"] == "EdDSA"
            and isinstance(hdr["kid"], str)
            and hdr["kid"]
            and hdr["typ"] == "x402-acceptance+jws"
        ):
            return MI()
        if not isinstance(body, dict) or not (
            isinstance(body.get("signer"), str) and body["signer"]
        ):
            return MI()
        jws = (parts, pb, sb, hdr)
    else:
        return MI()

    # ---- step 3 key step + signature
    if fmt == "eip712":
        sigtxt = env["signature"]
        ent = None
        for c in inp.get("chain") or []:
            if (
                isinstance(c, dict)
                and c.get("chainId") == cid
                and str(c.get("account", "")).lower() == "0x" + acct
            ):
                ent = c
                break
        if ent is None:
            return out(
                "key_unresolved",
                [],
                reason="chain_state_unavailable",
                policy_refusal=False,
            )
        digest = acceptance_digest(body, cid, acct)
        if not ent.get("code"):
            if not re.fullmatch(r"0x[0-9a-f]{130}", sigtxt):
                return out("malformed", ["signature_invalid"])
            if recover(digest, bytes.fromhex(sigtxt[2:]), True) != "0x" + acct:
                return out("malformed", ["signature_invalid"])
        else:
            if inp.get("contractAccounts", True) is False:
                return out(
                    "key_unresolved",
                    [],
                    reason="contract_accounts_unsupported",
                    policy_refusal=False,
                )
            if not re.fullmatch(r"0x([0-9a-f]{2})*", sigtxt):
                return out("malformed", ["signature_invalid"])
            call = None
            for c in ent.get("calls") or []:
                if (
                    c.get("digest") == "0x" + digest.hex()
                    and c.get("signature") == sigtxt
                ):
                    call = c
                    break
            if call is None:
                return out(
                    "key_unresolved",
                    [],
                    reason="chain_state_unavailable",
                    policy_refusal=False,
                )
            ret = call.get("returns")
            ok = False
            if (
                not call.get("revert")
                and isinstance(ret, str)
                and re.fullmatch(r"0x([0-9a-fA-F]{2})*", ret)
            ):
                rb = bytes.fromhex(ret[2:])
                ok = (
                    len(rb) >= 32
                    and rb[:32] == bytes.fromhex("1626ba7e") + b"\x00" * 28
                )
            if not ok:
                return out("malformed", ["signature_invalid"])
        verifier_ident = ("addr", "0x" + acct)
    else:
        parts, pb, sb, hdr = jws
        pol = trust.get("complete") is True
        ents = [
            k
            for k in (trust.get("keys") or [])
            if isinstance(k, dict) and k.get("kid") == hdr["kid"]
        ]
        if not ents:
            return out("key_unresolved", [], reason="key_missing", policy_refusal=pol)
        ent = ents[0]
        if ent.get("signer") != body["signer"]:
            return out(
                "key_unresolved", [], reason="signer_mismatch", policy_refusal=pol
            )
        kb = b64u_dec(ent.get("key"))
        if kb is None or len(kb) != 32 or not ed.key_ok(kb):
            return out("key_unresolved", [], reason="key_refused", policy_refusal=False)
        if not ed.verify(kb, (parts[0] + "." + parts[1]).encode("ascii"), sb):
            return out("malformed", ["signature_invalid"])
        verifier_ident = ("ed", kb)

    # ---- step 4 malformed pass
    conds = set()
    if jws is not None:
        try:
            if jws[1] != b64u_dec_payload_jcs(body):
                conds.add("acceptance_member_invalid")
        except Bad:
            conds.add("acceptance_member_invalid")

    def hex32(k):
        return isinstance(body.get(k), str) and HEX32.fullmatch(body[k]) is not None

    def strmem(k, nonempty=False):
        v = body.get(k)
        return isinstance(v, str) and (v != "" or not nonempty)

    def obj_ok(k, ks):
        o = body.get(k)
        return (
            isinstance(o, dict)
            and set(o) == set(ks)
            and all(isinstance(o[x], str) for x in ks)
        )

    v_ver = is_int(body.get("version")) and body["version"] == 0
    v_ctx, v_terms, v_out = (
        hex32("contextId"),
        hex32("termsDigest"),
        hex32("outcomeDigest"),
    )
    v_iss = strmem("deliveryIssuer", True)
    v_cp = strmem("confirmingParty")
    v_sig = strmem("signer", True)
    v_at = is_int(body.get("issuedAt")) and 0 <= body["issuedAt"] <= 2**53 - 1
    v_auth = obj_ok("authority", ("mode", "profile", "reference"))
    v_subj = obj_ok("subject", ("profile", "reference"))
    v_disp = isinstance(body.get("disposition"), str)
    if set(body) != KEYS11 or not all(
        (v_ver, v_ctx, v_terms, v_out, v_iss, v_cp, v_sig, v_at, v_auth, v_subj, v_disp)
    ):
        conds.add("acceptance_member_invalid")
    if v_disp and body["disposition"] not in ("accepted", "rejected", "disputed"):
        conds.add("acceptance_member_invalid")
    if v_iss:  # AR-33
        iss = body["deliveryIssuer"]
        if (v_cp and body["confirmingParty"] == iss) or (
            v_sig and body["signer"] == iss
        ) or verifier_ident[0] == "addr" and verifier_ident[1] in issuer_addrs(
            trust, iss
        ) or verifier_ident[0] == "ed" and verifier_ident[1] in issuer_ed_keys(
            trust, iss
        ):
            conds.add("acceptance_signer_is_issuer")
    if v_cp and body["confirmingParty"] == "":  # AR-34
        conds.add("confirming_party_absent")

    known = v_subj and body["subject"]["profile"] == "x402ev/1"
    subj = None
    terms_digs = []
    if known and v_iss:
        subj = load_subject(inp.get("subject"), trust, body["deliveryIssuer"])
        if (
            subj is not None
            and verifier_ident[0] == "ed"
            and verifier_ident[1] == subj["pub"]
        ):
            conds.add("acceptance_signer_is_issuer")
    if subj is not None:
        if v_ctx and v_subj:
            if (
                body["subject"]["reference"] != subj["ref"]
                or body["contextId"] != "0x" + subj["ref"][len("x402ev/1:sha256:") :]
            ):
                conds.add("acceptance_record_digest_mismatch")
        if v_out:
            if body["outcomeDigest"] != subj["outcome"]:
                conds.add("acceptance_outcome_digest_mismatch")
            if (
                inp.get("outcome") is not None
                and "0x" + hashlib.sha256(inp["outcome"]).hexdigest()
                != body["outcomeDigest"]
            ):
                conds.add("acceptance_outcome_digest_mismatch")
        if v_at and body["issuedAt"] < subj["time"]:
            conds.add("acceptance_precedes_outcome")
        terms_digs = offer_digests(
            inp.get("terms"), trust, body["deliveryIssuer"], subj
        )
        if terms_digs and v_terms and body["termsDigest"] not in terms_digs:
            conds.add("acceptance_terms_digest_mismatch")

    # ---- steps 5-9
    if conds:
        return out("malformed", conds)
    disp = body["disposition"]
    if not known:
        return out("unknown", [], disposition=disp, reason="profile_unavailable")
    if subj is None or not terms_digs:
        return out("unknown", [], disposition=disp, reason="evidence_unavailable")
    a = body["authority"]
    resolved = False
    if a == {"mode": "direct", "profile": "payer/0", "reference": ""}:
        resolved = (
            subj["payer"] is not None
            and body["signer"] == body["confirmingParty"] == subj["payer"]
        )
    elif a == {"mode": "declared", "profile": "declared-evidence/0", "reference": ""}:
        want = {
            "confirmingParty": body["confirmingParty"],
            "signer": body["signer"],
            "subjectProfile": body["subject"]["profile"],
            "subjectReference": body["subject"]["reference"],
        }
        resolved = any(
            isinstance(e, dict) and all(e.get(k) == v for k, v in want.items())
            for e in (trust.get("authority") or [])
        )
    if not resolved:
        return out("unknown", ["acceptance_authority_unresolved"], disposition=disp)
    return out("verified", [], disposition=disp)


def b64u_dec_payload_jcs(body):
    """The payload (raw segment bytes) must equal JCS(body): return JCS(body) bytes for comparison."""
    return jcs_bytes(body)
