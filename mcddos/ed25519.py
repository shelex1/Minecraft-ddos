"""Pure-Python Ed25519 (RFC 8032) — keygen + sign + verify.

Used for signed-chat sessions (Minecraft 1.19.3+). No external deps.
Uses affine twisted-Edwards formulas (verified against RFC 8032 vectors).
Performance is fine: chat signing happens once per bot join, not per packet.
"""
import hashlib

_p = 2 ** 255 - 19
_q = 2 ** 252 + 27742317777372353535851937790883648493


def _inv(a, m=_p):
    return pow(a, m - 2, m)


_d = -121665 * _inv(121666) % _p
_I = pow(2, (_p - 1) // 4, _p)


def _recover_x(y, sign):
    xx = (y * y - 1) * _inv(_d * y * y + 1) % _p
    x = pow(xx, (_p + 3) // 8, _p)
    if (x * x - xx) % _p != 0:
        x = (x * _I) % _p
    if x % 2 != sign:
        x = _p - x
    return x


_By = 4 * _inv(5) % _p
_Bx = _recover_x(_By, 0)
_B = (_Bx, _By)  # affine (x, y)


def _add(P, Q):
    x1, y1 = P
    x2, y2 = Q
    return ((x1 * y2 + x2 * y1) * _inv(1 + _d * x1 * x2 * y1 * y2) % _p,
            (y1 * y2 + x1 * x2) * _inv(1 - _d * x1 * x2 * y1 * y2) % _p)


def _dbl(P):
    x1, y1 = P
    return ((2 * x1 * y1) * _inv(1 + _d * x1 * x1 * y1 * y1) % _p,
            (y1 * y1 + x1 * x1) * _inv(1 - _d * x1 * x1 * y1 * y1) % _p)


def _scalarmult(P, e):
    Q = (0, 1)
    while e:
        if e & 1:
            Q = _add(P, Q)
        P = _dbl(P)
        e >>= 1
    return Q


def _compress(P):
    x, y = P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(s):
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    x = _recover_x(y, s[31] >> 7)
    return (x, y)


def _clamped(a):
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a


def public_key(seed: bytes) -> bytes:
    h = hashlib.sha512(seed).digest()
    a = _clamped(int.from_bytes(h[:32], "little"))
    return _compress(_scalarmult(_B, a))


def sign(msg: bytes, seed: bytes) -> bytes:
    h = hashlib.sha512(seed).digest()
    a = _clamped(int.from_bytes(h[:32], "little"))
    prefix = h[32:]
    A = _compress(_scalarmult(_B, a))
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % _q
    R = _compress(_scalarmult(_B, r))
    k = int.from_bytes(hashlib.sha512(R + A + msg).digest(), "little") % _q
    S = (r + k * a) % _q
    return R + S.to_bytes(32, "little")


def verify(msg: bytes, sig: bytes, pk: bytes) -> bool:
    if len(sig) != 64:
        return False
    R = sig[:32]
    S = int.from_bytes(sig[32:], "little")
    if S >= _q:
        return False
    A = _decompress(pk)
    r = _decompress(R)
    k = int.from_bytes(hashlib.sha512(R + pk + msg).digest(), "little") % _q
    left = _scalarmult(_B, S)
    right = _add(r, _scalarmult(A, k))
    return left == right
