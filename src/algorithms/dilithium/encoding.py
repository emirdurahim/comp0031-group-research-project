"""CRYSTALS-Dilithium (FIPS 204) - Encoding & Decoding Layer.

Bit-packing routines for serialising/deserialising public keys,
secret keys, and signatures.

Mirrors FIPS 204 Algorithms 16-29.
"""

from __future__ import annotations

from typing import List

from .math import Q, N, D, Poly, mod_pos


# ===================================================================
# Generic bit-packing helpers
# ===================================================================

def _bit_pack(poly: Poly, a: int, b: int) -> bytes:
    """Pack polynomial coefficients into bytes."""
    total = a + b
    if total == 0:
        return b'\x00' * 0
    bits_per = total.bit_length()
    # Pack into a big integer bit by bit, then convert to bytes
    acc = 0
    bit_pos = 0
    for c in poly:
        val = a - c  # map [-b, a] -> [0, a+b]
        acc |= (val << bit_pos)
        bit_pos += bits_per
    byte_len = (bit_pos + 7) // 8
    return acc.to_bytes(byte_len, 'little')


def _bit_unpack(data: bytes, a: int, b: int) -> Poly:
    """Unpack polynomial coefficients from bytes."""
    total = a + b
    bits_per = total.bit_length()
    mask = (1 << bits_per) - 1
    acc = int.from_bytes(data, 'little')
    coeffs: List[int] = []
    for _ in range(N):
        val = acc & mask
        coeffs.append(a - val)
        acc >>= bits_per
    return coeffs


# ===================================================================
# SimpleBitPack / SimpleBitUnpack (unsigned, for t1)
# ===================================================================

def _simple_bit_pack(poly: Poly, bound: int) -> bytes:
    """Pack unsigned coefficients in [0, bound] into bytes."""
    bits_per = bound.bit_length()
    acc = 0
    bit_pos = 0
    for c in poly:
        acc |= (c << bit_pos)
        bit_pos += bits_per
    byte_len = (bit_pos + 7) // 8
    return acc.to_bytes(byte_len, 'little')


def _simple_bit_unpack(data: bytes, bound: int) -> Poly:
    """Unpack unsigned coefficients from bytes."""
    bits_per = bound.bit_length()
    mask = (1 << bits_per) - 1
    acc = int.from_bytes(data, 'little')
    coeffs: List[int] = []
    for _ in range(N):
        val = acc & mask
        coeffs.append(val)
        acc >>= bits_per
    return coeffs


# ===================================================================
# Public key encoding  (FIPS 204 Algorithm 22/23)
# ===================================================================

def pk_encode(rho: bytes, t1: List[Poly]) -> bytes:
    """Encode public key: rho || BitPack(t1[0]) || ... || BitPack(t1[k-1])."""
    result = bytearray(rho)
    for poly in t1:
        result.extend(_simple_bit_pack(poly, (1 << 10) - 1))
    return bytes(result)


def pk_decode(pk: bytes, k: int) -> tuple[bytes, List[Poly]]:
    """Decode public key into (rho, t1)."""
    rho = pk[:32]
    poly_bytes = 320  # 256 * 10 / 8
    t1 = []
    offset = 32
    for _ in range(k):
        t1.append(_simple_bit_unpack(pk[offset:offset + poly_bytes], (1 << 10) - 1))
        offset += poly_bytes
    return rho, t1


# ===================================================================
# Secret key encoding  (FIPS 204 Algorithm 24/25)
# ===================================================================

def sk_encode(rho: bytes, K: bytes, tr: bytes,
              s1: List[Poly], s2: List[Poly], t0: List[Poly],
              eta: int) -> bytes:
    """Encode secret key: rho || K || tr || s1 || s2 || t0."""
    result = bytearray(rho)   # 32 bytes
    result.extend(K)            # 32 bytes
    result.extend(tr)           # 64 bytes
    for poly in s1:
        result.extend(_bit_pack(poly, eta, eta))
    for poly in s2:
        result.extend(_bit_pack(poly, eta, eta))
    t0_upper = 1 << (D - 1)  # 2^12 = 4096
    for poly in t0:
        result.extend(_bit_pack(poly, t0_upper, t0_upper - 1))
    return bytes(result)


def sk_decode(sk: bytes, k: int, l: int, eta: int) -> tuple[bytes, bytes, bytes, List[Poly], List[Poly], List[Poly]]:
    """Decode secret key into (rho, K, tr, s1, s2, t0)."""
    rho = sk[:32]
    K = sk[32:64]
    tr = sk[64:128]
    offset = 128

    # s1/s2: eta determines bits per coeff
    eta_bits = (2 * eta).bit_length()
    s_bytes = N * eta_bits // 8

    s1 = []
    for _ in range(l):
        s1.append(_bit_unpack(sk[offset:offset + s_bytes], eta, eta))
        offset += s_bytes

    s2 = []
    for _ in range(k):
        s2.append(_bit_unpack(sk[offset:offset + s_bytes], eta, eta))
        offset += s_bytes

    # t0: 13 bits per coeff
    t0_upper = 1 << (D - 1)
    t0_bytes = N * D // 8  # 256 * 13 / 8 = 416
    t0 = []
    for _ in range(k):
        t0.append(_bit_unpack(sk[offset:offset + t0_bytes], t0_upper, t0_upper - 1))
        offset += t0_bytes

    return rho, K, tr, s1, s2, t0


# ===================================================================
# Signature encoding  (FIPS 204 Algorithm 26/27)
# ===================================================================

def sig_encode(ctilde: bytes, z: List[Poly], h: List[List[int]],
               gamma1: int, omega: int, k: int) -> bytes:
    """Encode signature: ctilde || z || hint."""
    result = bytearray(ctilde)

    # Pack z
    for poly in z:
        result.extend(_bit_pack(poly, gamma1, gamma1 - 1))

    # Pack hints: omega + k bytes
    hint_buf = bytearray(omega + k)
    idx = 0
    for i in range(k):
        for j in h[i]:
            hint_buf[idx] = j
            idx += 1
        hint_buf[omega + i] = idx
    result.extend(hint_buf)

    return bytes(result)


def sig_decode(sig: bytes, l: int, k: int, gamma1: int,
               omega: int, ctilde_len: int) -> tuple[bytes, List[Poly], List[List[int]]] | None:
    """Decode signature into (ctilde, z, h)."""
    ctilde = sig[:ctilde_len]
    offset = ctilde_len

    # Unpack z
    if gamma1 == (1 << 17):
        z_bytes = 576  # 256 * 18 / 8
    else:
        z_bytes = 640  # 256 * 20 / 8

    z = []
    for _ in range(l):
        z.append(_bit_unpack(sig[offset:offset + z_bytes], gamma1, gamma1 - 1))
        offset += z_bytes

    # Unpack hints
    hint_buf = sig[offset:offset + omega + k]
    h: List[List[int]] = []
    idx = 0
    for i in range(k):
        end = hint_buf[omega + i]
        if end < idx or end > omega:
            return None  # malformed
        positions = []
        for p in range(idx, end):
            if p > idx and hint_buf[p] <= hint_buf[p - 1]:
                return None  # not sorted / duplicate
            positions.append(hint_buf[p])
        h.append(positions)
        idx = end

    # Remaining hint positions must be zero
    for p in range(idx, omega):
        if hint_buf[p] != 0:
            return None

    return ctilde, z, h


# ===================================================================
# w1 encoding  (FIPS 204 Algorithm 28 - used in signing/verification)
# ===================================================================

def w1_encode(w1: List[Poly], gamma2: int) -> bytes:
    """Encode the high bits of w for hashing."""
    m = (Q - 1) // (2 * gamma2)
    result = bytearray()
    for poly in w1:
        result.extend(_simple_bit_pack(poly, m))
    return bytes(result)
