#!/usr/bin/env python3
"""Pure-Python Ed25519 (RFC 8032) primitives for PhotonPort verifiers.

Dependency-free so receipt and appcast verification run identically on
developer Macs and CI runners without pip installs.

Scope and safety:
- ``verify`` is the production surface. It operates only on public data
  (public key, message, signature), so the lack of constant-time arithmetic
  is acceptable.
- ``sign``/``public_key`` exist ONLY for test fixtures. Never load production
  private key material into this module; production receipts are signed by
  external tooling and this repo verifies them.
"""

from __future__ import annotations

import hashlib

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


def _recover_x(y: int, sign_bit: int) -> int | None:
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1) % _P
    if x2 == 0:
        if sign_bit:
            return None
        return 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _I % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign_bit:
        x = _P - x
    return x


_BY = 4 * _inv(5) % _P
_BX = _recover_x(_BY, 0)
assert _BX is not None
_B = (_BX, _BY, 1, _BX * _BY % _P)
_ZERO = (0, 1, 1, 0)


def _add(p: tuple[int, int, int, int], q: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = 2 * t1 * t2 * _D % _P
    dd = 2 * z1 * z2 % _P
    e = b - a
    f = dd - c
    g = dd + c
    h = b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(scalar: int, point: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    result = _ZERO
    while scalar:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _compress(point: tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = point
    zi = _inv(z)
    x = x * zi % _P
    y = y * zi % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(data: bytes) -> tuple[int, int, int, int] | None:
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign_bit = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign_bit)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _sha512_int(*parts: bytes) -> int:
    digest = hashlib.sha512()
    for part in parts:
        digest.update(part)
    return int.from_bytes(digest.digest(), "little")


def verify(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
    """RFC 8032 Ed25519 verification. Returns False on ANY malformed input."""
    if not isinstance(public_key_bytes, (bytes, bytearray)) or len(public_key_bytes) != 32:
        return False
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != 64:
        return False
    if not isinstance(message, (bytes, bytearray)):
        return False
    public_key_bytes = bytes(public_key_bytes)
    signature = bytes(signature)
    a = _decompress(public_key_bytes)
    if a is None:
        return False
    r_bytes = signature[:32]
    r = _decompress(r_bytes)
    if r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    k = _sha512_int(r_bytes, public_key_bytes, bytes(message)) % _L
    sb = _mul(s, _B)
    rka = _add(r, _mul(k, a))
    x1, y1, z1, _ = sb
    x2, y2, z2, _ = rka
    return (x1 * z2 - x2 * z1) % _P == 0 and (y1 * z2 - y2 * z1) % _P == 0


def _clamped_scalar(seed: bytes) -> tuple[int, bytes]:
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    digest = hashlib.sha512(seed).digest()
    a = int.from_bytes(digest[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, digest[32:]


def public_key(private_seed: bytes) -> bytes:
    """TEST FIXTURES ONLY. Derive the public key for a 32-byte seed."""
    a, _ = _clamped_scalar(private_seed)
    return _compress(_mul(a, _B))


def sign(private_seed: bytes, message: bytes) -> bytes:
    """TEST FIXTURES ONLY. Deterministic RFC 8032 signature."""
    a, prefix = _clamped_scalar(private_seed)
    pub = _compress(_mul(a, _B))
    r = _sha512_int(prefix, bytes(message)) % _L
    r_bytes = _compress(_mul(r, _B))
    k = _sha512_int(r_bytes, pub, bytes(message)) % _L
    s = (r + k * a) % _L
    return r_bytes + int.to_bytes(s, 32, "little")
