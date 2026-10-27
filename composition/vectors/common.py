"""Shared primitives for the composition vectors: RFC 8785 JCS, strict base64 forms, Ed25519 verify (RFC 8032)
with the key and signature rules of both specifications, and the two record identities.

Implemented here, from the specification texts only:
  - CNSLabs x402 acceptance record (tag draft-2026-10-27): JWS form (AR-15..AR-20), body rules (AR-4..AR-6),
    statementId (AR-21). The EIP-712 form (AR-8..AR-14) is NOT implemented.
  - Work-acceptance record, schema trilatic.acceptance-receipt/1.2, profile 1.4.1: signature section 5 and the
    record digest of section 4.
"""

import base64
import hashlib
import json
import re


# ---------------------------------------------------------------- JCS (RFC 8785), integers and strings only
def jcs(v):
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        if abs(v) > 2**53 - 1:
            raise ValueError("integer outside the I-JSON range")
        return str(v)
    if isinstance(v, float):
        raise ValueError("non-integer number")
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
    raise ValueError("unsupported value")


def jcs_bytes(v):
    return jcs(v).encode("utf-8")


def sha256_hex(b):
    return hashlib.sha256(b).hexdigest()


# ---------------------------------------------------------------- base64 forms
def b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64url_strict(s):
    """Unpadded base64url with zero unused trailing bits (AR-15); ValueError otherwise."""
    if (
        not isinstance(s, str)
        or not re.fullmatch(r"[A-Za-z0-9_-]*", s)
        or len(s) % 4 == 1
    ):
        raise ValueError("not canonical base64url")
    b = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if b64url(b) != s:
        raise ValueError("not canonical base64url")
    return b


def b64std_strict(s):
    """Padded standard base64, canonical (work-acceptance spec section 5); ValueError otherwise."""
    if (
        not isinstance(s, str)
        or not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", s)
        or len(s) % 4
    ):
        raise ValueError("not canonical base64")
    b = base64.b64decode(s, validate=True)
    if base64.b64encode(b).decode("ascii") != s:
        raise ValueError("not canonical base64")
    return b


# ---------------------------------------------------------------- Ed25519 verify (RFC 8032 section 5.1.7)
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
O = (0, 1, 1, 0)


def _decode_point(b):
    if len(b) != 32:
        return None
    b = bytearray(b)
    x_sign = b[31] >> 7
    b[31] &= 0x7F
    y = int.from_bytes(b, "little")
    if y >= P:
        return None
    y2 = y * y % P
    u, v = (y2 - 1) % P, (D * y2 + 1) % P
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


_B = _decode_point((4 * pow(5, P - 2, P) % P).to_bytes(32, "little"))


def is_prime_order_point(b):
    """Canonical encoding of a point of order exactly L (AR-19; work-acceptance section 5 key rule)."""
    A = _decode_point(b)
    return bool(A) and not _eq(A, O) and _eq(_mul(A, L), O)


def ed25519_verify(sig, msg, pub, strict_r=False):
    """RFC 8032 cofactorless check. strict_r adds AR-20's rule that R is a point of order exactly L."""
    if len(sig) != 64 or len(pub) != 32:
        return False
    A, R = _decode_point(pub), _decode_point(sig[:32])
    if not A or not R:
        return False
    if strict_r and not is_prime_order_point(sig[:32]):
        return False
    S = int.from_bytes(sig[32:], "little")
    if S >= L:
        return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), "little") % L
    return _eq(_mul(_B, S), _add(R, _mul(A, h)))


# ---------------------------------------------------------------- identities
WAR_PROFILE = "war/1.2"


def war_identity(receipt_body):
    """Subject identity under profile war/1.2: prefix + hex SHA-256 of JCS(receipt) (work-acceptance section 4)."""
    return WAR_PROFILE + ":sha256:" + sha256_hex(jcs_bytes(receipt_body))


def statement_id(body):
    """AR-21."""
    return "x402accept/0:sha256:" + sha256_hex(jcs_bytes(body))
