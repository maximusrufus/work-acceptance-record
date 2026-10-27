"""Work-acceptance record verifier, profile 1.4.2 (schema trilatic.acceptance-receipt/1.2).

Reference verifier using only the Python standard library. It implements Ed25519 (with the profile 1.3 key rule), canonical-input and strict-time rules of profile 1.4.2 (WAR_VERIFY_STRICT=1 re-raises an internal error instead of refusing),
JCS (RFC 8785), the RFC 3161 imprint, time and accuracy read from the token's signed TSTInfo, and (profile 1.4)
the RFC 3161 authority-signature checks, embedded below. No network, no dependencies.
Usage:  python war_verify.py VECTOR.json [VECTOR.json ...]   -> prints AGREE/DIFF per vector, exit 1 on any DIFF
        python war_verify.py --outcome VECTOR.json           -> prints the computed outcome as JSON
        python war_verify.py --tsa-roots ROOTS.pem [--tsa-roots ...] ...  -> also evaluate TSA signatures against these
                                                                anchors (outcome field tsa_signature; profile 1.4)
"""

import datetime
import hashlib
import json
import os
import re
import sys

SCHEMA_V1 = "trilatic.acceptance-receipt/1"
SCHEMA_V11 = "trilatic.acceptance-receipt/1.1"
SCHEMA_V12 = "trilatic.acceptance-receipt/1.2"
RESULT_VOCAB = ["pass", "fail", "not-evaluated", "error"]


def b64_strict(s):
    """The single base64 decode path: canonical base64 or ValueError (see tsa_verify.b64_strict)."""
    return _tsa_module().b64_strict(s)


def _b64_or_empty(s):
    """For optional input blobs (tokens, criteria file, anchors): a non-canonical value is bytes that can match
    nothing (empty), so it takes the same path as a malformed blob: hash/imprint mismatch, token failed."""
    try:
        return b64_strict(s)
    except ValueError:
        return b""


# ---------------------------------------------------------------- Ed25519 (RFC 8032, verify only)
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
O = (0, 1, 1, 0)


def _decode_point(b):
    b = bytearray(b)
    x_sign = b[31] >> 7
    b[31] &= 0x7F
    y = int.from_bytes(b, "little")
    if y >= P:
        return None
    y2 = y * y % P
    u = (y2 - 1) % P
    v = (D * y2 + 1) % P
    x = u * pow(v, 3, P) * pow(u * pow(v, 7, P), (P - 5) // 8, P) % P
    vx2 = v * x * x % P
    if vx2 != u:
        if vx2 == (-u) % P:
            x = x * SQRT_M1 % P
        else:
            return None
    if x == 0 and x_sign == 1:
        return None
    if (x & 1) != x_sign:
        x = (-x) % P
    return (x, y, 1, x * y % P)


def _add(p1, p2):
    X1, Y1, Z1, T1 = p1
    X2, Y2, Z2, T2 = p2
    A = (Y1 - X1) * (Y2 - X2) % P
    B = (Y1 + X1) * (Y2 + X2) % P
    C = T1 * 2 * D * T2 % P
    Dd = Z1 * 2 * Z2 % P
    E, F, G, H = B - A, Dd - C, Dd + C, B + A
    return (E * F % P, G * H % P, F * G % P, E * H % P)


def _mul(pt, k):
    r, q = O, pt
    while k > 0:
        if k & 1:
            r = _add(r, q)
        q = _add(q, q)
        k >>= 1
    return r


def _eq(p1, p2):
    return (p1[0] * p2[2] - p2[0] * p1[2]) % P == 0 and (
        p1[1] * p2[2] - p2[1] * p1[2]
    ) % P == 0


_BY = 4 * pow(5, P - 2, P) % P
_B = _decode_point(_BY.to_bytes(32, "little"))


def verify_ed25519(sig, msg, pub):
    if len(sig) != 64 or len(pub) != 32:
        return False
    A, R = _decode_point(pub), _decode_point(sig[:32])
    if not A or not R:
        return False
    S = int.from_bytes(sig[32:], "little")
    if S >= L:
        return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), "little") % L
    return _eq(_mul(_B, S), _add(R, _mul(A, h)))


def key_is_canonical_prime_order(pub):
    """Key rule (profile 1.3): canonical encoding of a point of prime order L."""
    if not pub or len(pub) != 32:
        return False
    A = _decode_point(pub)
    if not A or _eq(A, O):
        return False
    return _eq(_mul(A, L), O)


# ---------------------------------------------------------------- canonical JSON
def _num(v):
    """ECMAScript Number::toString (RFC 8785 section 3.2.2.3). JSON numbers are IEEE doubles, so an integer beyond
    2**53 is formatted as the double it parses to, as a JavaScript verifier sees it."""
    if isinstance(v, bool):
        raise ValueError("bool")
    if isinstance(v, int) and abs(v) <= 2**53:
        return str(v)
    f = float(v)
    if f != f or f in (float("inf"), float("-inf")):
        raise ValueError("NaN and Infinity are not valid JSON numbers")
    if f == 0:
        return "0"
    sign = "-" if f < 0 else ""
    mant, _, exp = repr(abs(f)).partition(
        "e"
    )  # repr is the shortest round-trip digit string, as in ECMAScript
    ip, _, fp = mant.partition(".")
    digits = ip + fp
    n = len(ip) + (int(exp) if exp else 0)
    lead = len(digits) - len(digits.lstrip("0"))
    digits = digits.lstrip("0")
    n -= lead
    digits = digits.rstrip("0") or "0"
    k = len(digits)
    if k <= n <= 21:
        out = digits + "0" * (n - k)
    elif 0 < n <= 21:
        out = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        es = ("+" if e >= 0 else "-") + str(abs(e))
        out = digits + "e" + es if k == 1 else digits[0] + "." + digits[1:] + "e" + es
    return sign + out


def jcs(v):
    """RFC 8785: keys sorted by UTF-16 code units, strings escape only quote, backslash and controls."""
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, (int, float)):
        return _num(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ",".join(jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v, key=lambda k: k.encode("utf-16-be"))
        return (
            "{"
            + ",".join(
                json.dumps(k, ensure_ascii=False) + ":" + jcs(v[k]) for k in keys
            )
            + "}"
        )
    raise ValueError("unsupported value in receipt")


def canonical_v1(v):
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, float):
        if not v.is_integer():
            raise ValueError("non-integer number in receipt")
        return str(int(v))
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=True)
    if isinstance(v, list):
        return "[" + ",".join(canonical_v1(x) for x in v) + "]"
    if isinstance(v, dict):
        return (
            "{"
            + ",".join(canonical_v1(k) + ":" + canonical_v1(v[k]) for k in sorted(v))
            + "}"
        )
    raise ValueError("unsupported value in receipt")


def canonical_for(body):
    schema = body.get("schema")
    if schema == SCHEMA_V1:
        return canonical_v1(body)
    if schema in (SCHEMA_V11, SCHEMA_V12):
        s = body.get("suite")
        if (
            body.get("canonicalization") != "JCS-RFC8785"
            or not isinstance(s, dict)
            or s.get("digest") != "sha-256"
            or s.get("signature") != "Ed25519"
            or len(s) != 2
        ):
            raise ValueError(
                "This receipt declares a canonicalization or suite this verifier does not support."
            )
        return jcs(body)
    raise ValueError("Unsupported receipt version: " + str(schema)[:60])


# ---------------------------------------------------------------- RFC 3161 imprint and time (signed TSTInfo)


def _accuracy_at(tsr, i):
    if i + 1 >= len(tsr) or tsr[i] != 0x30:
        return None
    end = i + 2 + tsr[i + 1]
    ms, j, any_ = 0.0, i + 2, False
    while j < end and j + 1 < len(tsr):
        tag, ln = tsr[j], tsr[j + 1]
        n = int.from_bytes(tsr[j + 2 : j + 2 + ln], "big")
        if tag == 0x02:
            ms += n * 1000
        elif tag == 0x80:
            ms += n
        elif tag == 0x81:
            ms += n / 1000
        else:
            return None
        any_ = True
        j += 2 + ln
    return ms if any_ else None


def _fmt_ms(ms):
    t = datetime.datetime.fromtimestamp(ms // 1000, datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S"
    )
    return f"{t}.{ms % 1000:03d}Z" if ms % 1000 else t + "Z"


def _iso_from_gen(g, up=False):
    """GeneralizedTime to ISO-8601 UTC at millisecond precision, strict DER (RFC 3161 / X.690 11.7):
    YYYYMMDDHHMMSS[.f*[1-9]]Z. Only 'Z' (no offset), only '.' (not ','), a fraction must be non-empty with no trailing
    zero, and the calendar must be real (month 1-12, day valid for the month incl. leap years, hour 0-23, minute and
    second 0-59). Anything else is no usable time (None); this never raises.
    A fraction is kept (as .mmm, omitted when zero); the sub-millisecond remainder is dropped (round DOWN) or, with
    up=True, rounds the time UP to the next ms."""
    try:
        m = re.fullmatch(r"(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d*[1-9]))?Z", g, re.ASCII)
        if not m:
            return None
        y, mo, d, h, mi, sec = (int(x) for x in m.groups()[:6])
        datetime.datetime(y, mo, d, h, mi, sec)  # ValueError on an impossible date or time (also year 0)
        base = f"{m[1]}-{m[2]}-{m[3]}T{m[4]}:{m[5]}:{m[6]}"
        digits = m[7] or ""
        ms = int((digits + "000")[:3])
        rem = any(c != "0" for c in digits[3:])
        if not (up and rem):
            return f"{base}.{ms:03d}Z" if ms else base + "Z"
        return _fmt_ms(_ms(base + "Z") + ms + 1)
    except (ValueError, OverflowError, OSError, TypeError):
        return None


def tsr_time_for(tsr, digest):
    """Imprint, genTime and accuracy read from the token's signed TSTInfo (RFC 3161 2.4.2), never from other bytes:
    TimeStampResp or ContentInfo -> SignedData -> encapContentInfo (id-ct-TSTInfo) -> TSTInfo. Anything else in the
    response, such as PKIStatusInfo.statusString, is unsigned and is not read."""
    no = {"imprint": False, "time": None, "accuracy_ms": None}
    try:
        T = _tsa_module()
        ci = T._find_content_info(T.parse_one(tsr)).children()
        if T.oid_str(ci[0]) != "1.2.840.113549.1.7.2":
            return no
        encap = T.parse_one(ci[1].val).children()[2].children()
        if T.oid_str(encap[0]) != "1.2.840.113549.1.9.16.1.4":
            return no
        tst = T.parse_one(T.parse_one(encap[1].val).val).children()
        imprint = tst[2].children()
        if T.oid_str(imprint[0].children()[0]) != "2.16.840.1.101.3.4.2.1":
            return no  # the imprint must be SHA-256 by OID; same-length digests under other algorithms do not match
        if imprint[1].tag != 0x04 or imprint[1].val != digest or tst[4].tag != 0x18:
            return no
        acc = tst[5].raw if len(tst) > 5 and tst[5].tag == 0x30 else None
        return {
            "imprint": True,
            "time": _iso_from_gen(tst[4].val.decode("ascii", "replace")),
            "time_up": _iso_from_gen(tst[4].val.decode("ascii", "replace"), up=True),
            "accuracy_ms": _accuracy_at(acc, 0) if acc else None,
        }
    except (ValueError, IndexError, KeyError, AttributeError):
        return no


def _parse_ms(iso):
    """Epoch ms of 'YYYY-MM-DDTHH:MM:SS[.f{1,3}]Z' with a real calendar date and time, else None. Never raises."""
    try:
        m = re.fullmatch(
            r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z",
            iso,
            re.ASCII,
        )
        if not m:
            return None
        y, mo, d, h, mi, sec = (int(x) for x in m.groups()[:6])
        t = datetime.datetime(y, mo, d, h, mi, sec, tzinfo=datetime.timezone.utc)
        return int(t.timestamp()) * 1000 + int(((m[7] or "") + "000")[:3])
    except (ValueError, OverflowError, OSError, TypeError):
        return None


def _ms(iso):
    v = _parse_ms(iso)
    if v is None:
        raise ValueError("not an ISO-8601 UTC time")
    return v


def _present(x):
    """A time field that is stated at all: not absent (None) and not the empty string."""
    return x is not None and x != ""


# ---------------------------------------------------------------- structural type guard
# Every object, array and string the procedure reads must have the type it expects. A record or input of the wrong
# type is refused (never an exception): vector_outcome gives the step-1 refusal of vector 21; verify_receipt gives
# "not an acceptance receipt". Mirrored by typedDoc / typedInputs in receipt-core.js.
_LONE_SURROGATE = re.compile("[" + chr(0xD800) + "-" + chr(0xDFFF) + "]")


def _has_lone_surrogate(o):
    if isinstance(o, str):
        return bool(_LONE_SURROGATE.search(o))
    if isinstance(o, list):
        return any(_has_lone_surrogate(x) for x in o)
    if isinstance(o, dict):
        return any(_has_lone_surrogate(k) or _has_lone_surrogate(v) for k, v in o.items())
    return False


def _t_str(x):
    return x is None or isinstance(x, str)


def _t_obj(x):
    return x is None or isinstance(x, dict)


def _typed_party(p):
    return _t_obj(p) and (p is None or (_t_str(p.get("name")) and _t_str(p.get("key_id"))))


def _typed_doc(doc, keyset):
    """Envelope, keys file and (for schema 1.2) the body fields the checks read."""
    if not isinstance(doc, dict):
        return False
    rc, sg = doc.get("receipt"), doc.get("signature")
    if not isinstance(rc, dict) or not isinstance(sg, dict):
        return False
    if not (_t_str(sg.get("key_id")) and _t_str(rc.get("key_id")) and _t_obj(doc.get("timestamp"))):
        return False
    if keyset is not None:
        if not isinstance(keyset, dict):
            return False
        keys = keyset.get("keys")
        if keys is not None and not (
            isinstance(keys, list)
            and all(isinstance(k, dict) and _t_str(k.get("key_id")) for k in keys)
        ):
            return False
    if rc.get("schema") == SCHEMA_V12:
        parties = rc.get("parties")
        if not _t_obj(parties):
            return False
        if parties is not None and not (
            _typed_party(parties.get("checker")) and _typed_party(parties.get("producer"))
        ):
            return False
        c = rc.get("criteria")
        if not _t_obj(c) or (c is not None and not (_t_str(c.get("id")) and _t_str(c.get("version")))):
            return False
        results = rc.get("results")
        if results is not None and not (
            isinstance(results, list)
            and all(
                isinstance(r, dict)
                and isinstance(r.get("id"), str)
                and (r.get("required") is None or isinstance(r.get("required"), bool))
                for r in results
            )
        ):
            return False
        if not _t_obj(rc.get("human_review")):
            return False
    return True


def _typed_inputs(vec):
    if not isinstance(vec, dict) or not isinstance(vec.get("inputs"), dict):
        return False
    i = vec["inputs"]
    if not isinstance(i.get("keys"), dict) or not _typed_doc(i.get("receipt"), i["keys"]):
        return False
    for k in ("criteria_file_base64", "criteria_tsr_base64", "receipt_tsr_base64"):
        if not _t_str(i.get(k)):
            return False
    roots = i.get("tsa_roots_base64")
    if roots is not None and not (isinstance(roots, list) and all(isinstance(r, str) for r in roots)):
        return False
    return not _has_lone_surrogate(i)


# ---------------------------------------------------------------- record checks
def overall_verdict(results, human):
    if human and human.get("status") == "complete" and human.get("outcome") == "fail":
        return "fail"
    req = [r.get("result") for r in results if r.get("required") is not False]
    if "fail" in req:
        return "fail"
    if not req or any(x != "pass" for x in req):
        return "incomplete"
    return "pass"


def _dup_ids(keyset):
    """key_ids that appear more than once in the keys file: such an id names no single key (fail closed)."""
    ids = [k.get("key_id") for k in (keyset or {}).get("keys") or []]
    return {i for i in ids if isinstance(i, str) and ids.count(i) > 1}


def _key_of(keyset, kid):
    """Decoded public key for kid from the keys file (first entry): bytes; None if kid has no entry;
    False if the entry is not canonical base64 (a rejected key)."""
    if kid in _dup_ids(keyset):
        return False
    for k in (keyset or {}).get("keys") or []:
        if k.get("key_id") == kid:
            try:
                return b64_strict(k.get("public_key_base64"))
            except ValueError:
                return False
    return None


def _same_key(keyset, a, b):
    """True when key_ids a and b are equal, or both resolve through the keys file to the same decoded public key
    (one key under two ids is one key). The comparison is on decoded bytes, never on the strings."""
    if not a or not b:
        return False
    if a == b:
        return True
    ka, kb = _key_of(keyset, a), _key_of(keyset, b)
    return isinstance(ka, bytes) and ka == kb


def _key_bad(keyset, *kids):
    """A party's key entry that is not canonical base64: its key cannot be compared, so fail closed."""
    return any(kid and _key_of(keyset, kid) is False for kid in kids)


def independence_of(parties, keyset=None, claimed=None):
    chk = (parties or {}).get("checker") or {}
    prod = (parties or {}).get("producer") or {}
    name = str(prod.get("name") or "").strip().lower()
    if not name or name in ("unspecified", "unknown"):
        return "undeclared"
    if name == str(chk.get("name") or "").strip().lower() or (
        _same_key(keyset, prod.get("key_id"), chk.get("key_id"))
    ):
        return "self-checked"
    if _key_bad(keyset, prod.get("key_id"), chk.get("key_id")):
        return "self-checked"  # fail closed: independence cannot be shown against a key that cannot be read
    if claimed == "independent" and any(
        kid is not None and (kid == "" or not isinstance(_key_of(keyset, kid), bytes))
        for kid in (prod.get("key_id"), chk.get("key_id"))
    ):
        # An independence claim rests on keys only when a key_id is STATED: a stated key_id must be non-empty and listed
        # exactly once. An absent or null key_id (a producer does not sign) leaves the claim resting on the names.
        return "self-checked"
    return "independent"


def _no_constant(name):
    raise ValueError("NaN and Infinity are not valid JSON")


def _id_pairs(items, cd=None):
    """Sorted (id, required) pairs, duplicates kept, ids ordered by UTF-16 code units. Ill-typed items raise
    ValueError (the criteria file could not be read)."""
    if cd is not None and not isinstance(cd, dict):
        raise ValueError("criteria file is not an object")
    if items is None:
        items = []
    if not isinstance(items, list):
        raise ValueError("criteria is not a list")
    out = []
    for x in items:
        if not isinstance(x, dict) or not isinstance(x.get("id"), str):
            raise ValueError("criterion without a string id")
        rq = x.get("required")
        if not (rq is None or isinstance(rq, bool)):
            raise ValueError("required is not a boolean")
        out.append((x["id"], bool(rq)))
    return sorted(out, key=lambda p: (p[0].encode("utf-16-be", "surrogatepass"), p[1]))


def _check_v12(doc, out, criteria_bytes, criteria_tsr, keyset=None):
    b = doc["receipt"]
    problems, warnings = set(), set()
    if out.get("key_rejected"):
        problems.add("KEY_REJECTED")
    elif not out["signature"]:
        problems.add("SIGNATURE_INVALID")
    parties = b.get("parties") or {}
    chk, prod = parties.get("checker") or {}, parties.get("producer") or {}
    if _key_bad(keyset, chk.get("key_id"), prod.get("key_id")) or _dup_ids(keyset):
        problems.add("KEY_REJECTED")
    # compared with the SIGNED key identifier (the one the signing-key lookup uses), never with the unsigned envelope's
    signed_kid = b["key_id"] if "key_id" in b else doc["signature"].get("key_id")
    if chk.get("key_id") != signed_kid:
        problems.add("CHECKER_NOT_SIGNER")
    if _same_key(keyset, chk.get("key_id"), prod.get("key_id")):
        problems.add("KEY_COLLISION")
    derived = independence_of(parties, keyset, b.get("independence"))
    out["independence"] = b.get("independence")
    if derived != b.get("independence"):
        problems.add("INDEPENDENCE_INCONSISTENT")
    if b.get("independence") == "self-checked":
        warnings.add("SELF_CHECKED")
    if derived == "undeclared":
        warnings.add("PRODUCER_UNDECLARED")
    results = b.get("results") if isinstance(b.get("results"), list) else []
    if any(r.get("result") not in RESULT_VOCAB for r in results):
        problems.add("RESULT_VOCABULARY")
    out["verdict_recomputed"] = overall_verdict(results, b.get("human_review"))
    if out["verdict_recomputed"] != b.get("verdict"):
        problems.add("VERDICT_MISMATCH")

    c = b.get("criteria") or {}
    # criteria.sha256 must be exactly 64 lowercase hex digits; anything else (upper case included) can match nothing
    sha = c.get("sha256")
    claimed = sha if isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{64}", sha) else ""
    out["criteria_hash"] = "unavailable"
    out["criteria_committed_before_check"] = "unknown"
    if criteria_bytes is not None:
        h = hashlib.sha256(criteria_bytes).hexdigest()
        out["criteria_hash"] = "match" if h == claimed else "mismatch"
        if h != claimed:
            problems.add("CRITERIA_HASH_MISMATCH")
        else:
            try:
                cd = json.loads(
                    criteria_bytes.decode("utf-8"), parse_constant=_no_constant
                )
                want = _id_pairs(cd.get("criteria"), cd)
                got = _id_pairs(results)
                if (
                    want != got
                    or cd.get("criteria_set") != c.get("id")
                    or cd.get("version") != c.get("version")
                ):
                    problems.add("CRITERIA_RESULTS_MISMATCH")
            except Exception:
                problems.add("CRITERIA_UNREADABLE")

    committed, commit_acc, token_timed = c.get("committed_at"), 0, False  # committed: the claim, or the token time
    if criteria_tsr is not None:
        # an invalid or absent claimed hash is a digest no token can carry (33 bytes)
        digest = bytes.fromhex(claimed) if claimed else b"\x00" * 33
        t = tsr_time_for(criteria_tsr, digest)
        if not t["imprint"]:
            problems.add("CRITERIA_TIMESTAMP_MISMATCH")
        elif t["time"]:
            # committed_at is compared to the second; the time used for "before" keeps the exact fraction,
            # rounded UP to the next ms so a fraction can never make "before" easier
            if c.get("committed_at") != t["time"][:19] + "Z":
                problems.add("CRITERIA_TIME_MISMATCH")
            committed, commit_acc, token_timed = (
                t["time_up"],
                t["accuracy_ms"] or 0,
                True,
            )
    if not token_timed:
        warnings.add("CRITERIA_COMMITMENT_UNVERIFIED")

    ts = out["timestamp"]
    cover = ts.get("token_time") if ts.get("tsr") == "match" else None
    issued = b.get("issued_utc")
    # A stated time that is not a real ISO-8601 UTC time cannot be shown to be before anything: it is answered "no"
    # with the existing code CRITERIA_COMMITTED_AFTER_CHECK (fail closed). An absent or empty one is simply not stated.
    committed_ms = _parse_ms(committed) if _present(committed) else None
    issued_ms = _parse_ms(issued) if _present(issued) else None
    malformed = (_present(committed) and committed_ms is None) or (
        _present(issued) and issued_ms is None
    )
    cover_ms = _parse_ms(cover) if cover else None
    if cover_ms is not None and (issued_ms is None or cover_ms < issued_ms):
        ref_ms = cover_ms
    else:
        ref_ms = issued_ms
    ref_acc = (
        (ts.get("token_accuracy_ms") or 0)
        if cover_ms is not None and ref_ms == cover_ms
        else 0
    )
    if malformed:
        out["criteria_committed_before_check"] = "no"
        problems.add("RECEIPT_TIME_UNREADABLE")
    elif committed_ms is not None and ref_ms is not None:
        before = committed_ms + commit_acc < ref_ms - ref_acc
        out["criteria_committed_before_check"] = "yes" if before else "no"
        if not before:
            problems.add("CRITERIA_COMMITTED_AFTER_CHECK")
    out["problem_codes"] = sorted(problems)
    out["warning_codes"] = sorted(warnings)


def _key_bytes(entry):
    """A key that is not canonical base64 is a rejected key (KEY_REJECTED), like one of the wrong length."""
    try:
        return b64_strict(entry["public_key_base64"])
    except (ValueError, KeyError, TypeError):
        return None


def verify_receipt(
    doc, keyset, criteria_bytes=None, criteria_tsr=None, receipt_tsr=None
):
    out = {
        "signature": None,
        "timestamp": {"status": "none"},
        "problem_codes": [],
        "warning_codes": [],
    }
    if (
        not _typed_doc(doc, keyset)
        or not doc.get("receipt")
        or not doc.get("signature")
        or doc["signature"].get("alg") != "Ed25519"
    ):
        out["reason"] = "not an acceptance receipt"
        return out
    body = canonical_for(doc["receipt"]).encode("utf-8")
    signed_key_id = (
        doc["receipt"]["key_id"]
        if "key_id" in doc["receipt"]
        else doc["signature"].get("key_id")
    )
    entry = next(
        (
            k
            for k in (keyset or {}).get("keys") or []
            if k.get("key_id") == signed_key_id
        ),
        None,
    )
    if signed_key_id != doc["signature"].get("key_id"):
        out["signature"] = False
    elif entry and (
        signed_key_id in _dup_ids(keyset)
        or not key_is_canonical_prime_order(_key_bytes(entry))
    ):
        out["signature"], out["key_rejected"] = False, True
    elif not entry:
        out["signature"] = False
    else:
        try:
            out["signature"] = verify_ed25519(
                b64_strict(doc["signature"]["value"]),
                body,
                _key_bytes(entry),
            )
        except Exception:
            out["signature"] = False
    body_hash = hashlib.sha256(body).digest()
    t = doc.get("timestamp") or {"status": "none"}
    if t.get("status") == "granted":
        out["timestamp"] = {
            "status": "granted",
            "tsr": "not_provided",
            "token_time": None,
        }
        if receipt_tsr is not None:
            r = tsr_time_for(receipt_tsr, body_hash)
            out["timestamp"].update(
                tsr="match" if r["imprint"] else "mismatch",
                token_time=r["time"] if r["imprint"] else None,
                token_accuracy_ms=r["accuracy_ms"] if r["imprint"] else None,
            )
    if doc["receipt"].get("schema") == SCHEMA_V12:
        _check_v12(doc, out, criteria_bytes, criteria_tsr, keyset)
    elif out.get("key_rejected"):
        out["problem_codes"] = ["KEY_REJECTED"]
    elif not out["signature"]:
        out["problem_codes"] = ["SIGNATURE_INVALID"]
    return out


_TSA = None


# Embedded copy of tsa_verify.py (profile 1.4 authority-signature checks), standard library only.
_TSA_SOURCE = r'''#!/usr/bin/env python3
"""Stdlib-only RFC 3161 time-stamp-token SIGNATURE verifier.

Reports the TSA signature / chain result SEPARATELY from any work-acceptance
profile fields. Supports RSA PKCS#1 v1.5 and ECDSA (P-256/P-384), sha1/256/384/512.
RSASSA-PSS and other curves/algorithms are reported as "unsupported".

    verify_tsa_signature(tsr: bytes, roots: list[bytes]) -> dict
      status: verified | failed | untrusted | unsupported | no_signer
"""

import base64
import hashlib
import json
import re
import sys
from datetime import datetime, timezone

_B64_RE = re.compile(r"[A-Za-z0-9+/]*={0,2}")


def b64_strict(s):
    """Canonical base64 only (the one decode path of both verifiers; mirrors fromB64 in receipt-core.js): alphabet
    A-Z a-z 0-9 + /, '=' padding required (length % 4 == 0), no whitespace, and re-encoding the decoded bytes must give
    back the input exactly (so non-zero trailing bits are refused). Anything else raises ValueError."""
    if not isinstance(s, str) or len(s) % 4 != 0 or not _B64_RE.fullmatch(s):
        raise ValueError("non-canonical base64")
    try:
        raw = base64.b64decode(s, validate=True)
    except Exception as e:
        raise ValueError("non-canonical base64") from e
    if base64.b64encode(raw).decode("ascii") != s:
        raise ValueError("non-canonical base64")
    return raw

MAX_DEPTH = 6

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_TST_INFO = "1.2.840.113549.1.9.16.1.4"
OID_RSA = "1.2.840.113549.1.1.1"
OID_PSS = "1.2.840.113549.1.1.10"
OID_EC = "1.2.840.10045.2.1"
OID_EKU = "2.5.29.37"
OID_SKI = "2.5.29.14"
OID_BASIC_CONSTRAINTS = "2.5.29.19"
OID_TIMESTAMPING = "1.3.6.1.5.5.7.3.8"
OID_CN = "2.5.4.3"

HASH_OIDS = {
    "1.3.14.3.2.26": ("sha1", hashlib.sha1),
    "2.16.840.1.101.3.4.2.1": ("sha256", hashlib.sha256),
    "2.16.840.1.101.3.4.2.2": ("sha384", hashlib.sha384),
    "2.16.840.1.101.3.4.2.3": ("sha512", hashlib.sha512),
}
# signature algorithm OID -> hash OID (None = take from digestAlgorithm)
RSA_SIG_OIDS = {
    OID_RSA: None,
    "1.2.840.113549.1.1.5": "1.3.14.3.2.26",
    "1.2.840.113549.1.1.11": "2.16.840.1.101.3.4.2.1",
    "1.2.840.113549.1.1.12": "2.16.840.1.101.3.4.2.2",
    "1.2.840.113549.1.1.13": "2.16.840.1.101.3.4.2.3",
}


class Failed(Exception):
    pass


class Untrusted(Exception):
    pass


class Unsupported(Exception):
    pass


# ---------------------------------------------------------------- DER ------
class Node:
    __slots__ = ("raw", "tag", "val")

    def __init__(self, tag, val, raw):
        self.tag, self.val, self.raw = tag, val, raw

    def children(self):
        out, off = [], 0
        while off < len(self.val):
            n, off = parse(self.val, off)
            out.append(n)
        return out


def parse(data, off=0):
    """Parse one TLV at off. Returns (Node, next_offset)."""
    start = off
    if off + 2 > len(data):
        raise ValueError("truncated DER")
    tag = data[off]
    if tag & 0x1F == 0x1F:
        raise ValueError("high-tag-number form unsupported")
    off += 1
    ln = data[off]
    off += 1
    if ln == 0x80:
        raise ValueError("indefinite length unsupported")
    if ln & 0x80:
        nb = ln & 0x7F
        if nb > 4 or off + nb > len(data):
            raise ValueError("bad length")
        ln = int.from_bytes(data[off : off + nb], "big")
        off += nb
    if off + ln > len(data):
        raise ValueError("length exceeds data")
    return Node(tag, data[off : off + ln], data[start : off + ln]), off + ln


def parse_one(data):
    n, end = parse(data, 0)
    if end != len(data):
        raise ValueError("trailing bytes after DER object")
    return n


def oid_str(node):
    if node.tag != 0x06 or not node.val:
        raise ValueError("not an OID")
    v, parts, acc = node.val, [], 0
    for b in v:
        acc = (acc << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(acc)
            acc = 0
    first = parts[0]
    head = [first // 40, first % 40] if first < 80 else [2, first - 80]
    return ".".join(str(x) for x in head + parts[1:])


def int_val(node):
    return int.from_bytes(node.val, "big", signed=True)


def uint_val(node):
    return int.from_bytes(node.val, "big")


def parse_time(node):
    s = node.val.decode("ascii")
    if node.tag == 0x17:  # UTCTime
        fmt = "%y%m%d%H%M%SZ" if len(s) == 13 else "%y%m%d%H%MZ"
        d = datetime.strptime(s, fmt)
        # RFC 5280: YY >= 50 -> 19YY, else 20YY (strptime pivots at 69)
        yy = int(s[:2])
        d = d.replace(year=(1900 + yy) if yy >= 50 else (2000 + yy))
    elif node.tag == 0x18:  # GeneralizedTime
        base, frac = s.rstrip("Z"), ""
        if "." in base:
            base, frac = base.split(".", 1)
        d = datetime.strptime(base, "%Y%m%d%H%M%S")
        if frac:
            d = d.replace(microsecond=int((frac + "000000")[:6]))
    else:
        raise ValueError("not a time")
    return d.replace(tzinfo=timezone.utc)


def iso(d):
    s = d.strftime("%Y-%m-%dT%H:%M:%S")
    if d.microsecond:
        s += ("." + "%06d" % d.microsecond).rstrip("0")
    return s + "Z"


def name_cn(name_raw):
    """Best-effort CN (else first RDN value) of a DER Name."""
    try:
        first = None
        for rdn in parse_one(name_raw).children():
            for atv in rdn.children():
                k, v = atv.children()
                txt = _decode_str(v)
                if oid_str(k) == OID_CN:
                    return txt
                if first is None:
                    first = txt
        return first or ""
    except Exception:
        return ""


def _decode_str(v):
    if v.tag == 0x1E:
        return v.val.decode("utf-16-be", "replace")
    try:
        return v.val.decode("utf-8")
    except UnicodeDecodeError:
        return v.val.decode("latin-1")


# --------------------------------------------------------- certificates ----
class Cert:
    def __init__(self, der):
        self.der = der
        c = parse_one(der)
        if c.tag != 0x30:
            raise ValueError("certificate not a SEQUENCE")
        tbs, sigalg, sigval = c.children()
        self.tbs_raw = tbs.raw
        self.sigalg_oid = oid_str(sigalg.children()[0])
        self.sigalg_params = (sigalg.children() + [None])[1]
        self.sig = sigval.val[1:]  # drop unused-bits byte
        f = tbs.children()
        i = 0
        if f[0].tag == 0xA0:
            i = 1
        self.serial = f[i].val
        self.issuer_raw = f[i + 2].raw
        validity = f[i + 3].children()
        self.not_before = parse_time(validity[0])
        self.not_after = parse_time(validity[1])
        self.subject_raw = f[i + 4].raw
        spki = f[i + 5]
        self.spki_raw = spki.raw
        alg, bits = spki.children()
        self.key_oid = oid_str(alg.children()[0])
        self.rsa = None
        if self.key_oid == OID_RSA:
            k = parse_one(bits.val[1:]).children()
            self.rsa = (uint_val(k[0]), uint_val(k[1]))
        self.ec = None
        if self.key_oid == OID_EC:
            curve = oid_str(alg.children()[1])
            pt = bits.val[1:]
            if (
                curve in CURVES
                and len(pt) == 1 + 2 * ((CURVES[curve][0].bit_length() + 7) // 8)
                and pt[0] == 4
            ):
                m = (len(pt) - 1) // 2
                self.ec = (
                    curve,
                    int.from_bytes(pt[1 : 1 + m], "big"),
                    int.from_bytes(pt[1 + m :], "big"),
                )
            else:
                self.ec_curve_oid = curve
        self.eku = None
        self.ski = None
        self.is_ca = False  # basicConstraints cA, DEFAULT FALSE (RFC 5280 4.2.1.9)
        for x in f[i + 6 :]:
            if x.tag != 0xA3:
                continue
            for ext in parse_one(x.val).children():
                parts = ext.children()
                oid = oid_str(parts[0])
                body = parts[-1].val  # OCTET STRING content
                if oid == OID_EKU:
                    self.eku = [oid_str(o) for o in parse_one(body).children()]
                elif oid == OID_SKI:
                    self.ski = parse_one(body).val
                elif oid == OID_BASIC_CONSTRAINTS:
                    bc = parse_one(body).children()
                    self.is_ca = (
                        bool(bc)
                        and bc[0].tag == 0x01
                        and bc[0].val not in (b"", b"\x00")
                    )

    @property
    def cn(self):
        return name_cn(self.subject_raw) or "?"


def rsa_pkcs1_verify(cert, hash_oid, signed, sig):
    if cert.rsa is None:
        raise Failed(
            "issuer/signer key type %s does not match an RSA signature algorithm"
            % cert.key_oid
        )
    n, e = cert.rsa
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        raise Failed("signature length does not match RSA modulus")
    em = pow(int.from_bytes(sig, "big"), e, n).to_bytes(k, "big")
    digest = HASH_OIDS[hash_oid][1](signed).digest()
    alg_null = (
        bytes([0x30, 0x0D, 0x06])
        + bytes([len(_oid_der(hash_oid))])
        + _oid_der(hash_oid)
        + b"\x05\x00"
    )
    alg_bare = bytes(
        [0x30, len(_oid_der(hash_oid)) + 2, 0x06, len(_oid_der(hash_oid))]
    ) + _oid_der(hash_oid)
    for alg in (alg_null, alg_bare):
        body = alg + b"\x04" + bytes([len(digest)]) + digest
        di = b"\x30" + bytes([len(body)]) + body
        pad = k - len(di) - 3
        if pad >= 8 and em == b"\x00\x01" + b"\xff" * pad + b"\x00" + di:
            return
    raise Failed("RSA PKCS#1 v1.5 signature does not verify")


OID_MGF1 = "1.2.840.113549.1.1.8"


def pss_params(node):
    """RSASSA-PSS-params (RFC 8017 A.2.3) -> (hash_oid, salt_len). MGF1 with the same hash and trailerField 1 only."""
    h, mgf_h, salt, trailer = "1.3.14.3.2.26", "1.3.14.3.2.26", 20, 1  # ASN.1 defaults
    for f in node.children() if node is not None and node.tag == 0x30 else []:
        inner = parse_one(f.val)
        if f.tag == 0xA0:
            h = oid_str(inner.children()[0])
        elif f.tag == 0xA1:
            k = inner.children()
            if oid_str(k[0]) != OID_MGF1:
                raise Unsupported(
                    "RSASSA-PSS mask generation %s not supported" % oid_str(k[0])
                )
            mgf_h = oid_str(k[1].children()[0])
        elif f.tag == 0xA2:
            salt = uint_val(inner)
        elif f.tag == 0xA3:
            trailer = uint_val(inner)
    if h not in HASH_OIDS:
        raise Unsupported("hash algorithm %s not supported" % h)
    if mgf_h != h:
        raise Unsupported(
            "RSASSA-PSS with an MGF1 hash different from the message hash"
        )
    if trailer != 1:
        raise Unsupported("RSASSA-PSS trailerField %d" % trailer)
    return h, salt


def rsa_pss_verify(cert, hash_oid, salt_len, signed, sig):
    """EMSA-PSS-VERIFY (RFC 8017 9.1.2) with MGF1 over the same hash."""
    if cert.rsa is None:
        raise Failed(
            "issuer/signer key type %s does not match an RSA signature algorithm"
            % cert.key_oid
        )
    n, e = cert.rsa
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        raise Failed("signature length does not match RSA modulus")
    hfn = HASH_OIDS[hash_oid][1]
    h_len = hfn().digest_size
    em_bits = n.bit_length() - 1
    em_len = (em_bits + 7) // 8
    m = pow(int.from_bytes(sig, "big"), e, n)
    if m >= 1 << (8 * em_len):
        raise Failed("RSASSA-PSS signature does not verify")
    em = m.to_bytes(em_len, "big")
    if em_len < h_len + salt_len + 2 or em[-1] != 0xBC:
        raise Failed("RSASSA-PSS signature does not verify")
    masked, hh = em[: em_len - h_len - 1], em[em_len - h_len - 1 : -1]
    top = 8 * em_len - em_bits
    if masked[0] >> (8 - top) if top else 0:
        raise Failed("RSASSA-PSS signature does not verify")
    mask, c = b"", 0
    while len(mask) < len(masked):
        mask += hfn(hh + c.to_bytes(4, "big")).digest()
        c += 1
    db = bytearray(x ^ y for x, y in zip(masked, mask))
    db[0] &= 0xFF >> top
    ps = em_len - h_len - salt_len - 2
    if any(db[:ps]) or db[ps] != 0x01:
        raise Failed("RSASSA-PSS signature does not verify")
    salt = bytes(db[len(db) - salt_len :]) if salt_len else b""
    if hfn(b"\x00" * 8 + hfn(signed).digest() + salt).digest() != hh:
        raise Failed("RSASSA-PSS signature does not verify")


def _oid_der(s):
    p = [int(x) for x in s.split(".")]
    out = bytearray([p[0] * 40 + p[1]])
    for x in p[2:]:
        chunk = [x & 0x7F]
        x >>= 7
        while x:
            chunk.append((x & 0x7F) | 0x80)
            x >>= 7
        out += bytes(reversed(chunk))
    return bytes(out)


# ---------------------------------------------------------------- ECDSA ----
# NIST curves: p, a, b, Gx, Gy, n  (verification only; public data, no secrets)
CURVES = {
    "1.2.840.10045.3.1.7": (  # P-256
        0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
        0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
        0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
        0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    ),
    "1.3.132.0.34": (  # P-384
        2**384 - 2**128 - 2**96 + 2**32 - 1,
        2**384 - 2**128 - 2**96 + 2**32 - 1 - 3,
        0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF,
        0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7,
        0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F,
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
    ),
}
ECDSA_SIG_OIDS = {
    "1.2.840.10045.4.1": "1.3.14.3.2.26",
    "1.2.840.10045.4.3.2": "2.16.840.1.101.3.4.2.1",
    "1.2.840.10045.4.3.3": "2.16.840.1.101.3.4.2.2",
    "1.2.840.10045.4.3.4": "2.16.840.1.101.3.4.2.3",
    OID_EC: None,  # bare id-ecPublicKey: hash from digestAlgorithm
}


def _ec_add(P, Q, p, a):
    if P is None:
        return Q
    if Q is None:
        return P
    if P[0] == Q[0]:
        if (P[1] + Q[1]) % p == 0:
            return None
        lam = (3 * P[0] * P[0] + a) * pow(2 * P[1], -1, p) % p
    else:
        lam = (Q[1] - P[1]) * pow(Q[0] - P[0], -1, p) % p
    x = (lam * lam - P[0] - Q[0]) % p
    return (x, (lam * (P[0] - x) - P[1]) % p)


def _ec_mul(k, P, p, a):
    R = None
    while k:
        if k & 1:
            R = _ec_add(R, P, p, a)
        P = _ec_add(P, P, p, a)
        k >>= 1
    return R


def ecdsa_verify(cert, hash_oid, signed, sig):
    if cert.ec is None:
        if cert.key_oid != OID_EC:
            raise Failed(
                "issuer/signer key type %s does not match an ECDSA signature algorithm"
                % cert.key_oid
            )
        raise Unsupported(
            "EC curve %s not supported" % getattr(cert, "ec_curve_oid", "?")
        )
    curve, qx, qy = cert.ec
    p, a, b, gx, gy, n = CURVES[curve]
    if (qy * qy - (qx**3 + a * qx + b)) % p:
        raise Failed("EC public key is not on the curve")
    try:
        rs = parse_one(sig).children()
        r, s = uint_val(rs[0]), uint_val(rs[1])
    except (ValueError, IndexError):
        raise Failed("malformed ECDSA signature")
    if not (0 < r < n and 0 < s < n):
        raise Failed("ECDSA r/s out of range")
    h = HASH_OIDS[hash_oid][1](signed).digest()
    e = int.from_bytes(h, "big")
    excess = len(h) * 8 - n.bit_length()
    if excess > 0:
        e >>= excess
    w = pow(s, -1, n)
    pt = _ec_add(
        _ec_mul(e * w % n, (gx, gy), p, a), _ec_mul(r * w % n, (qx, qy), p, a), p, a
    )
    if pt is None or pt[0] % n != r:
        raise Failed("ECDSA signature does not verify")


def verify_sig(cert, sig_oid, digest_oid, signed, sig, params=None):
    """Verify sig by cert's public key. Raises Failed / Unsupported."""
    if sig_oid == OID_PSS:
        h, salt = pss_params(params)
        return rsa_pss_verify(cert, h, salt, signed, sig)
    if sig_oid in RSA_SIG_OIDS:
        h = RSA_SIG_OIDS[sig_oid] or digest_oid
        if h not in HASH_OIDS:
            raise Unsupported("hash algorithm %s not supported" % h)
        return rsa_pkcs1_verify(cert, h, signed, sig)
    if sig_oid in ECDSA_SIG_OIDS:
        h = ECDSA_SIG_OIDS[sig_oid] or digest_oid
        if h not in HASH_OIDS:
            raise Unsupported("hash algorithm %s not supported" % h)
        return ecdsa_verify(cert, h, signed, sig)
    raise Unsupported(
        "signature algorithm %s not supported (RSA PKCS#1 v1.5, RSASSA-PSS and ECDSA P-256/P-384 only)"
        % sig_oid
    )


# ---------------------------------------------------------------- chain ----
def build_chain(signer, pool, roots, gen_dt):
    """Return list of Certs signer..anchor; raises Failed / Untrusted. Each issuer that is not an anchor must be valid at gen_dt."""
    chain = [signer]
    cur = signer
    for _ in range(MAX_DEPTH):
        for r in roots:
            if r.subject_raw == cur.subject_raw and r.spki_raw == cur.spki_raw:
                return chain  # cur IS a trusted root
        cands = [
            c
            for c in roots + pool
            if c.subject_raw == cur.issuer_raw and c.der != cur.der
        ]
        if not cands:
            raise Untrusted("no issuer found for %r" % cur.cn)
        last_err = None
        nxt = None
        for cand in cands:
            try:
                verify_sig(
                    cand, cur.sigalg_oid, None, cur.tbs_raw, cur.sig, cur.sigalg_params
                )
                nxt = cand
                break
            except Failed as e:
                last_err = e
        if nxt is None:
            # An anchor with the issuer's name but another key is not that issuer (anchors match by name and key): if
            # only anchors failed, no chain reaches a supplied anchor. A certificate carried in the token that fails is
            # a broken chain.
            if all(any(c.der == r.der for r in roots) for c in cands):
                raise Untrusted(
                    "no supplied anchor with the name and key that issued %r" % cur.cn
                )
            raise Failed("certificate %r: %s" % (cur.cn, last_err))
        # An issuer must be a CA, unless it is a provided trust anchor (anchors are trusted by configuration).
        # Without this, any end-entity certificate under a trusted root could vouch for a forged signer.
        anchor = any(
            r.subject_raw == nxt.subject_raw and r.spki_raw == nxt.spki_raw
            for r in roots
        )
        if not anchor and not nxt.is_ca:
            raise Failed(
                "issuer certificate %r is not a CA (basicConstraints cA is not TRUE)"
                % nxt.cn
            )
        if not anchor and not (nxt.not_before <= gen_dt <= nxt.not_after):
            raise Failed(
                "issuer certificate %r not valid at genTime %s" % (nxt.cn, iso(gen_dt))
            )
        chain.append(nxt)
        cur = nxt
        if cur.subject_raw == cur.issuer_raw:
            # self-signed: acceptable only if it is a provided root
            for r in roots:
                if r.subject_raw == cur.subject_raw and r.spki_raw == cur.spki_raw:
                    return chain
            raise Untrusted(
                "chain ends at self-signed %r which is not a provided root" % cur.cn
            )
    # depth exhausted: final check
    for r in roots:
        if r.subject_raw == cur.subject_raw and r.spki_raw == cur.spki_raw:
            return chain
    raise Untrusted("chain deeper than %d" % MAX_DEPTH)


# ----------------------------------------------------------------- main ----
def _result(status, reason, signer=None, chain=None, gen=None):
    return {
        "status": status,
        "reason": reason,
        "signer_subject": signer,
        "chain": chain or [],
        "gen_time": gen,
    }


def _find_content_info(top):
    kids = top.children()
    if kids and kids[0].tag == 0x06:
        return top  # bare ContentInfo
    if len(kids) >= 2 and kids[0].tag == 0x30 and kids[1].tag == 0x30:
        st = kids[0].children()
        if st and st[0].tag == 0x02 and int_val(st[0]) not in (0, 1):
            raise Failed("TimeStampResp status %d is not granted" % int_val(st[0]))
        return kids[1]
    if len(kids) == 1 and kids[0].tag == 0x30:
        raise Failed("TimeStampResp carries no token")
    raise ValueError("neither TimeStampResp nor ContentInfo")


OID_SIGNING_CERT = (
    "1.2.840.113549.1.9.16.2.12"  # ESS SigningCertificate (ESSCertID: SHA-1 certHash)
)
OID_SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47"  # ESS SigningCertificateV2 (RFC 5816; hashAlgorithm DEFAULT sha256)


def _check_ess_binding(attrs, signer):
    """RFC 3161 2.4.2 / RFC 5816: the signed attributes must bind the signer certificate by hash
    (SigningCertificate or SigningCertificateV2; the first ESSCertID names the signer)."""
    if attrs is None:
        raise Failed("no signed attributes, so no ESS signing-certificate binding")
    for a in attrs.children():
        ak = a.children()
        oid = oid_str(ak[0])
        if oid not in (OID_SIGNING_CERT, OID_SIGNING_CERT_V2):
            continue
        value = ak[1].children()[0]  # attrValues SET OF -> SigningCertificate(V2)
        cert_ids = value.children()[0].children()  # certs SEQUENCE OF ESSCertID(v2)
        if not cert_ids:
            raise Failed("ESS signing-certificate attribute lists no certificate")
        fields = cert_ids[0].children()
        if oid == OID_SIGNING_CERT:
            want, hfn = fields[0].val, hashlib.sha1
        else:
            hfn = hashlib.sha256
            if fields[0].tag == 0x30:  # explicit hashAlgorithm
                alg = oid_str(fields[0].children()[0])
                if alg not in HASH_OIDS:
                    raise Unsupported("ESS certHash algorithm %s not supported" % alg)
                hfn = HASH_OIDS[alg][1]
                fields = fields[1:]
            want = fields[0].val
        if hfn(signer.der).digest() != want:
            raise Failed(
                "ESS signing-certificate hash does not match the signer certificate"
            )
        return
    raise Failed("no ESS signing-certificate attribute in signed attributes")


def verify_tsa_signature(tsr, roots):
    signer_name, chain_names, gen_iso = None, [], None
    # Precedence (profile 1.4): failed if any check that can run fails; else no_signer; else unsupported; else
    # untrusted. no_signer and unsupported are deferred so the checks that can still run get their chance to fail.
    pending = []

    def defer(status, reason):
        if not pending or (status == "no_signer" and pending[0][0] != "no_signer"):
            pending[:] = [(status, reason)]

    def try_run(f):
        try:
            return f()
        except Unsupported as e:
            defer("unsupported", str(e))
            return None

    try:
        top = parse_one(tsr)
        ci = _find_content_info(top)
        ci_k = ci.children()
        if oid_str(ci_k[0]) != OID_SIGNED_DATA:
            raise ValueError("ContentInfo is not signedData")
        sd = parse_one(ci_k[1].val).children()  # [0] EXPLICIT -> SignedData
        encap = sd[2].children()
        if len(encap) < 2:
            raise ValueError("no eContent")
        econtent_type = oid_str(encap[0])
        if econtent_type != OID_TST_INFO:
            raise Failed("eContentType %s is not id-ct-TSTInfo" % econtent_type)
        econtent = parse_one(encap[1].val).val  # [0] { OCTET STRING }
        certs_der, signer_infos = [], None
        for n in sd[3:]:
            if n.tag == 0xA0:
                certs_der = [c.raw for c in n.children()]
            elif n.tag == 0x31:
                signer_infos = n

        tst = parse_one(econtent).children()
        gen_dt = parse_time(tst[4])
        gen_iso = iso(gen_dt)

        if signer_infos is None:
            return _result("no_signer", "SignedData has no signerInfos", gen=gen_iso)

        sis = signer_infos.children()
        if not sis:
            return _result("no_signer", "SignedData has empty signerInfos", gen=gen_iso)
        si = sis[0].children()
        sid = si[1]
        digest_oid = oid_str(si[2].children()[0])
        idx = 3
        attrs = None
        if si[idx].tag == 0xA0:
            attrs = si[idx]
            idx += 1
        sig_oid = oid_str(si[idx].children()[0])
        sig_params = (si[idx].children() + [None])[1]
        signature = si[idx + 1].val

        notes = ""
        digest_ok = digest_oid in HASH_OIDS
        content_hash = None
        if not digest_ok:
            defer("unsupported", "digest algorithm %s not supported" % digest_oid)
        else:
            hname, hfn = HASH_OIDS[digest_oid]
            if hname == "sha1":
                notes = " (note: SHA-1 digest accepted, weak)"
            content_hash = hfn(econtent).digest()

        if attrs is not None:
            md, ct = None, None
            for a in attrs.children():
                ak = a.children()
                if oid_str(ak[0]) == OID_MESSAGE_DIGEST:
                    md = parse_one(ak[1].children()[0].raw).val
                elif oid_str(ak[0]) == OID_CONTENT_TYPE:
                    ct = oid_str(ak[1].children()[0])
            # RFC 5652 5.3: with signedAttrs present, content-type is required and must equal eContentType
            if ct is None:
                raise Failed("signedAttrs lack contentType")
            if ct != econtent_type:
                raise Failed(
                    "contentType attribute %s does not match eContentType" % ct
                )
            if md is None:
                raise Failed("signedAttrs lack messageDigest")
            if digest_ok and md != content_hash:
                raise Failed("messageDigest does not match hash of TSTInfo")
            signed = b"\x31" + attrs.raw[1:]
        else:
            signed = econtent

        certs = []
        for d in certs_der:
            try:
                certs.append(Cert(d))
            except Exception:
                continue
        roots_p = []
        for d in roots:
            try:
                roots_p.append(Cert(d))
            except Exception:
                continue

        # locate the signer cert by sid, in the token's certificates or among those the relying party supplied
        signer = None
        for c in certs + roots_p:
            if sid.tag == 0x30:
                ik = sid.children()
                if c.issuer_raw == ik[0].raw and c.serial == ik[1].val:
                    signer = c
                    break
            elif sid.tag == 0x80 and c.ski == sid.val:
                signer = c
                break
        if signer is None:
            defer("no_signer", "signer certificate neither in the token nor supplied")
            return _result(pending[0][0], pending[0][1], gen=gen_iso)
        signer_name = signer.cn

        if digest_ok:
            try_run(
                lambda: verify_sig(
                    signer, sig_oid, digest_oid, signed, signature, sig_params
                )
            )
        try_run(lambda: _check_ess_binding(attrs, signer))

        if signer.eku is None or OID_TIMESTAMPING not in signer.eku:
            raise Failed("signer certificate lacks extKeyUsage id-kp-timeStamping")
        if not (signer.not_before <= gen_dt <= signer.not_after):
            raise Failed("genTime %s outside signer certificate validity" % gen_iso)

        untrusted = None
        try:
            chain = try_run(lambda: build_chain(signer, certs, roots_p, gen_dt))
            if chain:
                chain_names = [c.cn for c in chain]
        except Untrusted as e:
            untrusted = str(e)
        if pending:
            return _result(
                pending[0][0], pending[0][1], signer_name, chain_names, gen_iso
            )
        if untrusted:
            return _result("untrusted", untrusted, signer_name, chain_names, gen_iso)
        return _result(
            "verified",
            "signature, chain to provided root, EKU and validity OK" + notes,
            signer_name,
            chain_names,
            gen_iso,
        )
    except Unsupported as e:
        return _result("unsupported", str(e), signer_name, chain_names, gen_iso)
    except Untrusted as e:
        return _result("untrusted", str(e), signer_name, chain_names, gen_iso)
    except Failed as e:
        return _result("failed", str(e), signer_name, chain_names, gen_iso)
    except (ValueError, IndexError, KeyError) as e:
        return _result(
            "failed", "malformed token: %s" % e, signer_name, chain_names, gen_iso
        )


def load_roots(path):
    data = open(path, "rb").read()
    if b"-----BEGIN" not in data:
        return [data]
    out, cur = [], None
    for line in data.decode("ascii", "replace").splitlines():
        if line.startswith("-----BEGIN CERTIFICATE"):
            cur = []
        elif line.startswith("-----END CERTIFICATE"):
            if cur is not None:
                out.append(b64_strict("".join(cur)))
            cur = None
        elif cur is not None:
            cur.append(line.strip())
    return out


def main(argv):
    if len(argv) < 2 or "--roots" not in argv:
        print(
            "usage: tsa_verify.py TOKEN.tsr --roots ROOTS.pem [ROOTS2.pem ...]",
            file=sys.stderr,
        )
        return 2
    ri = argv.index("--roots")
    pos = [a for a in argv[1:ri]]
    if len(pos) != 1:
        print(
            "usage: tsa_verify.py TOKEN.tsr --roots ROOTS.pem [ROOTS2.pem ...]",
            file=sys.stderr,
        )
        return 2
    token_path = pos[0]
    roots = []
    for p in argv[ri + 1 :]:
        roots.extend(load_roots(p))
    res = verify_tsa_signature(open(token_path, "rb").read(), roots)
    print(json.dumps(res, indent=2))
    return 0 if res["status"] == "verified" else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
'''


def _tsa_module():
    """The RFC 3161 signature checker (tsa_verify.py), embedded above so this verifier stays one file."""
    global _TSA
    if _TSA is None:
        import types

        _TSA = types.ModuleType("tsa_verify")
        exec(compile(_TSA_SOURCE, "tsa_verify.py", "exec"), _TSA.__dict__)
    return _TSA


def tsa_tokens_present(i):
    """The tokens for which tsa_signature is reported: the criteria token if supplied, and the record token if the
    envelope says one was granted and it is supplied. Nothing is reported for an absent token."""
    present = {}
    if i.get("criteria_tsr_base64"):
        present["criteria"] = _b64_or_empty(i["criteria_tsr_base64"])
    env_ts = (
        (i["receipt"].get("timestamp") or {})
        if isinstance(i.get("receipt"), dict)
        else {}
    )
    if env_ts.get("status") == "granted" and i.get("receipt_tsr_base64"):
        present["receipt"] = _b64_or_empty(i["receipt_tsr_base64"])
    return present


def tsa_signature_outcome(i, roots):
    """Profile 1.4 outcome field. roots: list of DER certificates (relying-party trust anchors)."""
    tv = _tsa_module()
    return {
        k: tv.verify_tsa_signature(tok, roots)["status"]
        for k, tok in tsa_tokens_present(i).items()
    }


_REFUSED = {"refused": True, "reason": "unknown schema, canonicalization or suite"}


_INTERNAL_ERROR = {"refused": True, "reason": "internal error"}


def vector_outcome(vec, tsa_roots=None):
    """The outcome for a vector. An ill-typed input is the step-1 refusal (_typed_inputs). Anything unforeseen is
    {"refused": true, "reason": "internal error"}, a distinct answer so that it is never mistaken for a schema refusal.
    With WAR_VERIFY_STRICT=1 in the environment the exception is raised instead (tests and fuzzers set it)."""
    try:
        return _vector_outcome(vec, tsa_roots)
    except Exception:
        if os.environ.get("WAR_VERIFY_STRICT") == "1":
            raise
        return dict(_INTERNAL_ERROR)


def _vector_outcome(vec, tsa_roots=None):
    if not _typed_inputs(vec):
        return dict(_REFUSED)
    i = vec["inputs"]
    try:
        canonical_for(i["receipt"]["receipt"])
    except ValueError:
        return dict(_REFUSED)
    b64 = lambda k: _b64_or_empty(i[k]) if i.get(k) else None
    v = verify_receipt(
        i["receipt"],
        i["keys"],
        b64("criteria_file_base64"),
        b64("criteria_tsr_base64"),
        b64("receipt_tsr_base64"),
    )
    ts = v["timestamp"]
    out = {
        "signature_valid": v["signature"] is True,
        "problem_codes": v["problem_codes"],
        "warning_codes": v["warning_codes"],
        "independence": v.get("independence"),
        "criteria_hash": v.get("criteria_hash"),
        "criteria_committed_before_check": v.get("criteria_committed_before_check"),
        "verdict_stated": i["receipt"]["receipt"].get("verdict"),
        "verdict_recomputed": v.get("verdict_recomputed"),
        "receipt_timestamp": "none"
        if ts["status"] != "granted" or ts["tsr"] == "not_provided"
        else ("imprint_match" if ts["tsr"] == "match" else "imprint_mismatch"),
    }
    # tsa_signature (profile 1.4) is evaluated only against relying-party anchors: the vector's tsa_roots_base64 or
    # --tsa-roots. Without anchors the field is omitted, which is read as not_evaluated for each token present.
    roots = tsa_roots
    if roots is None and i.get("tsa_roots_base64") is not None:
        roots = [_b64_or_empty(r) for r in i["tsa_roots_base64"]]
    if roots and tsa_tokens_present(
        i
    ):  # an empty anchor list is "without anchors": not evaluated
        out["tsa_signature"] = tsa_signature_outcome(i, roots)
    return out


def _norm(o):
    return {k: sorted(x) if k.endswith("_codes") else x for k, x in o.items()}


def normalize_tsa(got, exp, i, accepted=None):
    """Absence of tsa_signature means not_evaluated for each token present (profile 1.4). A vector's
    tsa_signature_accepted lists, per token, other values that also conform; such a value reads as the expected one."""
    if "tsa_signature" in exp and "tsa_signature" not in got:
        got = dict(got)
        got["tsa_signature"] = {k: "not_evaluated" for k in tsa_tokens_present(i)}
    if accepted and isinstance(got.get("tsa_signature"), dict):
        ts = dict(got["tsa_signature"])
        for k, ok in accepted.items():
            if ts.get(k) in ok:
                ts[k] = exp["tsa_signature"][k]
        got = dict(got, tsa_signature=ts)
    return got


def main(argv):
    roots = None
    rest = []
    it = iter(argv)
    for a in it:
        if a == "--tsa-roots":
            roots = (roots or []) + _tsa_module().load_roots(next(it))
        else:
            rest.append(a)
    argv = rest
    if argv[:1] == ["--outcome"]:
        for f in argv[1:]:
            print(
                json.dumps(
                    vector_outcome(json.load(open(f, encoding="utf-8")), roots),
                    indent=1,
                    sort_keys=True,
                )
            )
        return 0
    bad = 0
    for f in argv:
        vec = json.load(open(f, encoding="utf-8"))
        exp = vec["expected"]
        got = normalize_tsa(
            vector_outcome(vec, roots),
            exp,
            vec.get("inputs", {}),
            vec.get("tsa_signature_accepted"),
        )
        g = _norm({k: got.get(k) for k in exp})
        ok = g == _norm(exp)
        print(("AGREE " if ok else "DIFF  ") + f.replace("\\", "/").split("/")[-1])
        if not ok:
            bad += 1
            for k in exp:
                if g.get(k) != _norm(exp).get(k):
                    print(f"    {k}: expected {exp[k]!r} got {got.get(k)!r}")
    print(f"{len(argv) - bad}/{len(argv)} agree")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
