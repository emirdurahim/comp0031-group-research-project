"""CRYSTALS-Dilithium (FIPS 204) - Hashing & Sampling Layer.

SHAKE-128/256 based sampling functions for generating the
public matrix A, secret vectors, masking vectors, and
challenge polynomials.

Functions mirror FIPS 204 Algorithms 30-35.
"""

from __future__ import annotations

import hashlib
import struct
from typing import List

from .math import Q, N, Poly


# ---------------------------------------------------------------------------
# SHAKE helpers
# ---------------------------------------------------------------------------

def _shake128(data: bytes, outlen: int) -> bytes:
    """SHAKE-128 extendable output."""
    return hashlib.shake_128(data).digest(outlen)


def _shake256(data: bytes, outlen: int) -> bytes:
    """SHAKE-256 extendable output."""
    return hashlib.shake_256(data).digest(outlen)


# ---------------------------------------------------------------------------
# CoeffFromThreeBytes  (FIPS 204 helper for RejNTTPoly)
# ---------------------------------------------------------------------------

def _coeff_from_three_bytes(b0: int, b1: int, b2: int) -> int | None:
    """Extract a coefficient < Q from 3 bytes (23-bit little-endian)."""
    z = b0 | (b1 << 8) | ((b2 & 0x7F) << 16)
    if z < Q:
        return z
    return None


# ---------------------------------------------------------------------------
# CoeffFromHalfByte  (FIPS 204 helper for RejBoundedPoly)
# ---------------------------------------------------------------------------

def _coeff_from_half_byte(b: int, eta: int) -> int | None:
    """Extract a small coefficient from a 4-bit nibble."""
    if eta == 2 and b < 15:
        return 2 - (b % 5)
    if eta == 4 and b < 9:
        return 4 - b
    return None


# ---------------------------------------------------------------------------
# RejNTTPoly  (FIPS 204 Algorithm 30)
# ---------------------------------------------------------------------------

def rej_ntt_poly(seed: bytes) -> Poly:
    """Rejection-sample a polynomial in NTT domain from SHAKE-128."""
    buf = _shake128(seed, 4096)
    coeffs: List[int] = []
    idx = 0
    while len(coeffs) < N:
        c = _coeff_from_three_bytes(buf[idx], buf[idx + 1], buf[idx + 2])
        idx += 3
        if c is not None:
            coeffs.append(c)
    return coeffs


# ---------------------------------------------------------------------------
# RejBoundedPoly  (FIPS 204 Algorithm 31)
# ---------------------------------------------------------------------------

def rej_bounded_poly(seed: bytes, eta: int) -> Poly:
    """Rejection-sample a polynomial with coefficients in [-eta, eta]."""
    buf = _shake256(seed, 4096)
    coeffs: List[int] = []
    idx = 0
    while len(coeffs) < N:
        byte = buf[idx]
        idx += 1
        z0 = byte & 0x0F
        z1 = byte >> 4
        c0 = _coeff_from_half_byte(z0, eta)
        if c0 is not None and len(coeffs) < N:
            coeffs.append(c0)
        c1 = _coeff_from_half_byte(z1, eta)
        if c1 is not None and len(coeffs) < N:
            coeffs.append(c1)
    return coeffs


# ---------------------------------------------------------------------------
# ExpandA  (FIPS 204 Algorithm 32)
# ---------------------------------------------------------------------------

def expand_a(rho: bytes, k: int, l: int) -> List[List[Poly]]:
    """Generate k x l matrix A_hat in NTT domain from seed rho."""
    A = []
    for i in range(k):
        row = []
        for j in range(l):
            seed = rho + bytes([j, i])
            row.append(rej_ntt_poly(seed))
        A.append(row)
    return A


# ---------------------------------------------------------------------------
# ExpandS  (FIPS 204 Algorithm 33)
# ---------------------------------------------------------------------------

def expand_s(rhoprime: bytes, k: int, l: int, eta: int) -> tuple[List[Poly], List[Poly]]:
    """Generate secret vectors s1 (length l) and s2 (length k)."""
    s1 = []
    for r in range(l):
        seed = rhoprime + struct.pack('<H', r)
        s1.append(rej_bounded_poly(seed, eta))
    s2 = []
    for r in range(k):
        seed = rhoprime + struct.pack('<H', l + r)
        s2.append(rej_bounded_poly(seed, eta))
    return s1, s2


# ---------------------------------------------------------------------------
# ExpandMask  (FIPS 204 Algorithm 34)
# ---------------------------------------------------------------------------

def _bit_unpack_mask(buf: bytes, gamma1: int) -> Poly:
    """Unpack polynomial with coefficients in [-(gamma1-1), gamma1]."""
    coeffs: List[int] = []
    if gamma1 == (1 << 17):
        # 18-bit packing: 9 bytes -> 4 coefficients
        for i in range(64):
            chunk = int.from_bytes(buf[9 * i : 9 * i + 9], 'little')
            for _ in range(4):
                val = chunk & 0x3FFFF
                coeffs.append(gamma1 - val)
                chunk >>= 18
    elif gamma1 == (1 << 19):
        # 20-bit packing: 5 bytes -> 2 coefficients
        for i in range(128):
            chunk = int.from_bytes(buf[5 * i : 5 * i + 5], 'little')
            val0 = chunk & 0xFFFFF
            val1 = (chunk >> 20) & 0xFFFFF
            coeffs.append(gamma1 - val0)
            coeffs.append(gamma1 - val1)
    return coeffs


def expand_mask(rhoprime: bytes, kappa: int, l: int, gamma1: int) -> List[Poly]:
    """Generate masking vector y (length l) from seed and counter."""
    if gamma1 == (1 << 17):
        byte_len = 576   # 256 * 18 / 8
    else:
        byte_len = 640   # 256 * 20 / 8
    y = []
    for r in range(l):
        seed = rhoprime + struct.pack('<H', kappa + r)
        buf = _shake256(seed, byte_len)
        y.append(_bit_unpack_mask(buf, gamma1))
    return y


# ---------------------------------------------------------------------------
# SampleInBall  (FIPS 204 Algorithm 35)
# ---------------------------------------------------------------------------

def sample_in_ball(ctilde: bytes, tau: int) -> Poly:
    """Sample sparse challenge polynomial with exactly tau nonzero coefficients."""
    buf = _shake256(ctilde, 1024)

    # First 8 bytes -> 64 sign bits
    sign = int.from_bytes(buf[:8], 'little')

    c = [0] * N
    pos = 8

    for i in range(256 - tau, 256):
        # Rejection: find j <= i
        while True:
            j = buf[pos]
            pos += 1
            if j <= i:
                break
        c[i] = c[j]
        c[j] = 1 - 2 * (sign & 1)
        sign >>= 1

    return c
