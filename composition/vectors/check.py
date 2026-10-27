"""Composition checker: verifies every vector in this directory and compares the result with its `expect`.

Scope: the CNSLabs x402 acceptance record (tag draft-2026-10-27) JWS form, as implemented here from its SPEC.md
(sections 3, 4.2, 4.3, 6, 7 and 8), with one subject profile, `war/1.2` (COMPOSITION.md), whose subject is a
work-acceptance record (schema trilatic.acceptance-receipt/1.2). EIP-712 records, the `x402ev/1` profile and terms
artifacts other than the subject record are not implemented: an EIP-712 envelope is treated as unsupported input.
Exit status 0 iff every vector matches.
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (
    WAR_PROFILE,
    b64std_strict,
    b64url_strict,
    ed25519_verify,
    is_prime_order_point,
    jcs,
    jcs_bytes,
    war_identity,
)

HEX32 = re.compile(r"^0x[0-9a-f]{64}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
UTC = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z$")
MEMBERS = {
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


class Refused(Exception):
    pass


def _loads(b):
    """I-JSON parse (AR-6): UTF-8, no duplicate names, integers only, no lone surrogates."""

    def hook(pairs):
        names = [k for k, _ in pairs]
        if len(names) != len(set(names)):
            raise ValueError("duplicate member")
        return dict(pairs)

    def bad_num(s):
        raise ValueError("non-integer number")

    text = b.decode("utf-8")
    v = json.loads(
        text, object_pairs_hook=hook, parse_float=bad_num, parse_constant=bad_num
    )
    jcs(v).encode("utf-8")  # raises on lone surrogates and out-of-range integers
    return v


def _utc_seconds_ceil(s):
    """issued_utc to Unix seconds; a fractional second rounds up (COMPOSITION.md 3.4)."""
    import calendar
    import datetime

    m = UTC.match(s) if isinstance(s, str) else None
    if not m:
        return None
    y, mo, d, h, mi, se = (int(x) for x in m.groups()[:6])
    try:
        datetime.datetime(y, mo, d, h, mi, se)
    except ValueError:
        return None
    t = calendar.timegm((y, mo, d, h, mi, se))
    return t + 1 if m.group(7) and int(m.group(7)) else t


def _issuer_keys(trust, issuer):
    out = []
    for e in trust.get("issuers", []):
        if e.get("issuer") == issuer:
            for k in e.get("keys", []):
                if "ed25519" in k:
                    try:
                        out.append((k.get("kid"), b64url_strict(k["ed25519"])))
                    except ValueError:
                        pass
    return out


def war_subject(subject_bytes, delivery_issuer, trust):
    """Authenticate a work-acceptance record under profile war/1.2 (COMPOSITION.md 3.2); None when unavailable."""
    if subject_bytes is None:
        return None
    try:
        env = _loads(subject_bytes)
        r, sig = env["receipt"], env["signature"]
        if not (isinstance(r, dict) and isinstance(sig, dict)):
            return None
        if (
            r.get("schema") != "trilatic.acceptance-receipt/1.2"
            or r.get("canonicalization") != "JCS-RFC8785"
        ):
            return None
        if (
            r.get("suite") != {"digest": "sha-256", "signature": "Ed25519"}
            or sig.get("alg") != "Ed25519"
        ):
            return None
        kid = r.get("key_id")
        if (
            not isinstance(kid, str)
            or sig.get("key_id") != kid
            or r["parties"]["checker"]["key_id"] != kid
        ):
            return None
        keys = [k for (k_id, k) in _issuer_keys(trust, delivery_issuer) if k_id == kid]
        if len(keys) != 1 or not is_prime_order_point(keys[0]):
            return None
        if not ed25519_verify(
            b64std_strict(sig["value"]), jcs_bytes(r), keys[0], strict_r=True
        ):
            return None
        digest = r["files"]["remediated"]["sha256"]
        crit = r["criteria"]["sha256"]
        t = _utc_seconds_ceil(r.get("issued_utc"))
        if not (
            isinstance(digest, str)
            and HEX64.match(digest)
            and isinstance(crit, str)
            and HEX64.match(crit)
        ):
            return None
        if t is None:
            return None
        payer = None
        pay = r.get("payment")
        if isinstance(pay, dict):
            net, who = pay.get("network"), pay.get("payer")
            if (
                isinstance(net, str)
                and re.fullmatch(r"eip155:[1-9][0-9]*", net)
                and isinstance(who, str)
                and re.fullmatch(r"0x[0-9a-fA-F]{40}", who)
            ):
                payer = net + ":" + who.lower()
        return {
            "identity": war_identity(r),
            "outcomeDigest": "0x" + digest,
            "outcomeTime": t,
            "termsDigest": "0x" + crit,
            "payer": payer,
            "key": keys[0],
        }
    except (ValueError, KeyError, TypeError, UnicodeDecodeError):
        return None


def _member_ok(body):
    if not isinstance(body, dict) or set(body) != MEMBERS:
        return False
    a, s = body["authority"], body["subject"]
    if not (
        isinstance(a, dict)
        and set(a) == {"mode", "profile", "reference"}
        and all(isinstance(a[k], str) for k in a)
    ):
        return False
    if not (
        isinstance(s, dict)
        and set(s) == {"profile", "reference"}
        and all(isinstance(s[k], str) for k in s)
    ):
        return False
    if type(body["version"]) is not int or body["version"] != 0:
        return False
    if type(body["issuedAt"]) is not int or not 0 <= body["issuedAt"] <= 2**53 - 1:
        return False
    if not all(
        isinstance(body[k], str) and HEX32.match(body[k])
        for k in ("contextId", "termsDigest", "outcomeDigest")
    ):
        return False
    if not all(
        isinstance(body[k], str)
        for k in ("deliveryIssuer", "confirmingParty", "signer", "disposition")
    ):
        return False
    return body["deliveryIssuer"] != "" and body["signer"] != ""


def verify(inp):
    """AR-35, JWS form only."""
    trust = inp.get("trust", {})
    if inp.get("record") is None:
        return {"result": "no_record", "conditions": []}
    bad = {"result": "malformed", "conditions": ["acceptance_member_invalid"]}
    # 2. preflight
    try:
        env = _loads(b64url_strict(inp["record"]))
        if (
            not isinstance(env, dict)
            or set(env) != {"format", "signature"}
            or env["format"] != "jws"
        ):
            return bad
        parts = env["signature"].split(".")
        if len(parts) != 3:
            return bad
        hdr = _loads(b64url_strict(parts[0]))
        payload_bytes = b64url_strict(parts[1])
        sig = b64url_strict(parts[2])
        if not (
            isinstance(hdr, dict)
            and set(hdr) == {"alg", "kid", "typ"}
            and hdr["alg"] == "EdDSA"
            and hdr["typ"] == "x402-acceptance+jws"
            and isinstance(hdr["kid"], str)
            and hdr["kid"]
        ):
            return bad
        body = _loads(payload_bytes)
        if (
            not isinstance(body, dict)
            or not isinstance(body.get("signer"), str)
            or not body["signer"]
        ):
            return bad
    except (ValueError, KeyError, TypeError, AttributeError, UnicodeDecodeError):
        return bad
    # 3. key step (AR-18, AR-19, then AR-17, AR-20)
    entries = [k for k in trust.get("keys", []) if k.get("kid") == hdr["kid"]]
    kids = [k.get("kid") for k in trust.get("keys", [])]
    if len(kids) != len(set(kids)):
        raise Refused("trust.keys lists one kid twice")
    complete = trust.get("complete") is True

    def unresolved(reason):
        return {
            "result": "key_unresolved",
            "conditions": [],
            "reason": reason,
            "policy_refusal": complete,
        }

    if not entries:
        return unresolved("key_missing")
    if entries[0].get("signer") != body["signer"]:
        return unresolved("signer_mismatch")
    try:
        key = b64url_strict(entries[0]["key"])
    except ValueError:
        return unresolved("key_refused")
    if not is_prime_order_point(key):
        return unresolved("key_refused")
    if not ed25519_verify(
        sig, (parts[0] + "." + parts[1]).encode("ascii"), key, strict_r=True
    ):
        return {"result": "malformed", "conditions": ["signature_invalid"]}
    # 4. malformed pass
    cond = set()
    if payload_bytes != jcs_bytes(body):
        cond.add("acceptance_member_invalid")
    formed = _member_ok(body)
    if not formed:
        cond.add("acceptance_member_invalid")
    profile = (
        body.get("subject", {}).get("profile")
        if isinstance(body.get("subject"), dict)
        else None
    )
    known = profile == WAR_PROFILE
    subj = (
        war_subject(inp.get("subject_bytes"), body.get("deliveryIssuer"), trust)
        if known
        else None
    )
    if formed:
        if body["disposition"] not in ("accepted", "rejected", "disputed"):
            cond.add("acceptance_member_invalid")
        di = body["deliveryIssuer"]
        listed = [k for _, k in _issuer_keys(trust, di)]
        if (
            body["confirmingParty"] == di
            or body["signer"] == di
            or key in listed
            or (subj is not None and key == subj["key"])
        ):
            cond.add("acceptance_signer_is_issuer")
        if body["confirmingParty"] == "":
            cond.add("confirming_party_absent")
        if subj is not None:
            if (
                body["subject"]["reference"] != subj["identity"]
                or body["contextId"] != "0x" + subj["identity"][-64:]
            ):
                cond.add("acceptance_record_digest_mismatch")
            if body["outcomeDigest"] != subj["outcomeDigest"]:
                cond.add("acceptance_outcome_digest_mismatch")
            if body["issuedAt"] < subj["outcomeTime"]:
                cond.add("acceptance_precedes_outcome")
            if body["termsDigest"] != subj["termsDigest"]:
                cond.add("acceptance_terms_digest_mismatch")
    if cond:
        return {"result": "malformed", "conditions": sorted(cond)}
    disp = body["disposition"]
    if not known:
        return {
            "result": "unknown",
            "conditions": [],
            "reason": "profile_unavailable",
            "disposition": disp,
        }
    if subj is None:
        return {
            "result": "unknown",
            "conditions": [],
            "reason": "evidence_unavailable",
            "disposition": disp,
        }
    a = body["authority"]
    ok = False
    if a == {"mode": "direct", "profile": "payer/0", "reference": ""}:
        ok = (
            subj["payer"] is not None
            and body["signer"] == body["confirmingParty"] == subj["payer"]
        )
    elif a == {"mode": "declared", "profile": "declared-evidence/0", "reference": ""}:
        want = {
            "confirmingParty": body["confirmingParty"],
            "signer": body["signer"],
            "subjectProfile": profile,
            "subjectReference": body["subject"]["reference"],
        }
        ok = any(e == want for e in trust.get("authority", []))
    if not ok:
        return {
            "result": "unknown",
            "conditions": ["acceptance_authority_unresolved"],
            "disposition": disp,
        }
    return {"result": "verified", "conditions": [], "disposition": disp}


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    files = sorted(f for f in os.listdir(here) if re.match(r"^C\d{2}-.*\.json$", f))
    if not files:
        print("no vectors found; run gen.py first")
        return 1
    fails = 0
    for f in files:
        v = json.load(open(os.path.join(here, f), encoding="utf-8"))
        inp = dict(v["inputs"])
        inp["subject_bytes"] = (
            b64url_strict(inp["subject"]) if inp.get("subject") is not None else None
        )
        got = verify(inp)
        exp = v["expect"]
        got_cmp = {k: got.get(k) for k in exp}
        ok = got_cmp == exp
        fails += not ok
        print(f"{'PASS' if ok else 'FAIL'} {v['id']}")
        print(f"     expected {json.dumps(exp, sort_keys=True)}")
        print(f"     actual   {json.dumps(got, sort_keys=True)}")
    print(f"{len(files) - fails}/{len(files)} vectors match")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
