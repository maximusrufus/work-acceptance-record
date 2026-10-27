"""Strict Ed25519 (RFC 8032) with the order checks of SPEC AR-19 / AR-20. Pure Python ints."""

import hashlib

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
I = pow(2, (P - 1) // 4, P)
IDENT = (0, 1, 1, 0)


def _add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    A = (y1 - x1) * (y2 - x2) % P
    B = (y1 + x1) * (y2 + x2) % P
    C = t1 * 2 * D * t2 % P
    Dd = z1 * 2 * z2 % P
    E, F, G, H = B - A, Dd - C, Dd + C, B + A
    return (E * F % P, G * H % P, F * G % P, E * H % P)


def _mul(s, pt):
    r = IDENT
    while s:
        if s & 1:
            r = _add(r, pt)
        pt = _add(pt, pt)
        s >>= 1
    return r


def _eq(a, b):
    return (a[0] * b[2] - b[0] * a[2]) % P == 0 and (a[1] * b[2] - b[1] * a[2]) % P == 0


def decode_point(b: bytes):
    """Return point or None if not a canonical encoding of a curve point."""
    if len(b) != 32:
        return None
    n = int.from_bytes(b, "little")
    sign = n >> 255
    y = n & ((1 << 255) - 1)
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        if sign:
            return None
        x = 0
    else:
        x = pow(x2, (P + 3) // 8, P)
        if (x * x - x2) % P != 0:
            x = x * I % P
        if (x * x - x2) % P != 0:
            return None
        if (x & 1) != sign:
            x = P - x
    return (x, y, 1, x * y % P)


_By = 4 * pow(5, P - 2, P) % P
B = decode_point(_By.to_bytes(32, "little"))


def has_order_L(pt) -> bool:
    if _eq(pt, IDENT):
        return False
    return _eq(_mul(L, pt), IDENT)


def key_ok(pub: bytes) -> bool:
    pt = decode_point(pub)
    return pt is not None and has_order_L(pt)


def verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    """AR-19 key + AR-20 signature checks, then cofactorless RFC 8032 5.1.7 equation."""
    A = decode_point(pub)
    if A is None or not has_order_L(A) or len(sig) != 64:
        return False
    R = decode_point(sig[:32])
    if R is None or not has_order_L(R):
        return False
    S = int.from_bytes(sig[32:], "little")
    if S >= L:
        return False
    k = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), "little") % L
    return _eq(_mul(S, B), _add(R, _mul(k, A)))
