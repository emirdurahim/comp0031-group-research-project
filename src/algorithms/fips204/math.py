"""CRYSTALS-Dilithium (FIPS 204) - Math Primitives Layer.

This module implements the low-level mathematical building blocks used by
the Dilithium key generation, signing, and verification algorithms.

All operations work over the polynomial ring:
    R_q = Z_q[X] / (X^256 + 1)

where q = 8,380,417.

Layers
------
1. Modular arithmetic helpers
2. NTT precomputed table (zetas)
3. NTT / Inverse NTT
4. Polynomial arithmetic (add, sub, pointwise multiply)
5. Bit manipulation  (power2round, decompose, high_bits, low_bits)
6. Hint operations  (make_hint, use_hint)
"""

from __future__ import annotations

from typing import List

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Modulus - prime, q = 2^23 - 2^13 + 1
Q: int = 8_380_417

#: Polynomial degree
N: int = 256

#: Primitive 256th root of unity mod Q (zeta^256 == 1 mod Q, zeta^128 != 1 mod Q)
ZETA: int = 1_753

#: d used in power2round (drop factor 2^d)
D: int = 13

#: Inverse of N mod Q  (N * N_INV == 1 mod Q)
N_INV: int = 8_347_681

# Type alias: a polynomial is a list of N integers in Z_q
Poly = List[int]


# ---------------------------------------------------------------------------
# 1. Modular arithmetic helpers
# ---------------------------------------------------------------------------

def reduce32(a: int) -> int:
    """Reduce a 32-bit integer a mod Q to the range (-Q, Q)."""
    t   = (a + (1 << 22)) >> 23
    out = a - t * Q
    return out


def mod_pos(a: int) -> int:
    "Return *a* mod Q, always in [0, Q-1]."
    return a % Q


# ---------------------------------------------------------------------------
# 2. NTT precomputed zeta table
# ---------------------------------------------------------------------------

def _compute_zetas() -> List[int]:
    """Precompute the powers of ZETA in bit-reversed order."""
    def _bit_rev8(i: int) -> int:
        result = 0
        for _ in range(8):
            result = (result << 1) | (i & 1)
            i >>= 1
        return result

    return [pow(ZETA, _bit_rev8(i), Q) for i in range(N)]


# Precomputed at import time so every call to ntt/intt uses the same table.
ZETAS: List[int] = _compute_zetas()


# ---------------------------------------------------------------------------
# 3. NTT and Inverse NTT
# ---------------------------------------------------------------------------

def ntt(f: Poly) -> Poly:
    """Forward Number Theoretic Transform (in-place on a copy)."""
    f = list(f)   # work on a copy
    k = 1         # ZETAS[0] = 1 is unused; real zetas start at index 1
    length = 128
    while length >= 1:
        start = 0
        while start < N:
            zeta = ZETAS[k]
            k += 1
            for j in range(start, start + length):
                t = reduce32(zeta * f[j + length])
                f[j + length] = f[j] - t
                f[j] = f[j] + t
            start += 2 * length
        length >>= 1
    return f


def intt(f: Poly) -> Poly:
    """Inverse NTT - transform back from NTT domain to coefficient domain."""
    f = list(f)   # work on a copy
    k = 255       # INTT uses zetas in reverse: k goes 255 -> 1
    length = 1
    while length <= 128:
        start = 0
        while start < N:
            zeta = Q - ZETAS[k]  # negate: -ZETAS[k] mod Q
            k -= 1
            for j in range(start, start + length):
                t = f[j]
                f[j] = t + f[j + length]
                f[j + length] = reduce32(zeta * (t - f[j + length]))
            start += 2 * length
        length <<= 1
    return [mod_pos(reduce32(N_INV * c)) for c in f]


# ---------------------------------------------------------------------------
# 4. Polynomial arithmetic
# ---------------------------------------------------------------------------

def poly_add(f: Poly, g: Poly) -> Poly:
    """Coefficient-wise addition: result[i] = (f[i] + g[i]) mod Q."""
    return [mod_pos(f[i] + g[i]) for i in range(N)]



def poly_sub(f: Poly, g: Poly) -> Poly:
    """Coefficient-wise subtraction: result[i] = (f[i] - g[i]) mod Q."""
    return [mod_pos(f[i] - g[i]) for i in range(N)]


def poly_pointwise(f: Poly, g: Poly) -> Poly:
    """Coefficient-wise multiplication in the NTT domain."""
    return [mod_pos(f[i] * g[i]) for i in range(N)]


def poly_multiply(f: Poly, g: Poly) -> Poly:
    """Full polynomial multiplication in R_q = Z_q[X]/(X^256 + 1)."""
    return intt(poly_pointwise(ntt(f), ntt(g)))


# ---------------------------------------------------------------------------
# 5. Bit manipulation: power2round and decompose
# ---------------------------------------------------------------------------

def power2round(r: int, d: int = D) -> tuple[int, int]:
    """Split *r* into high and low bits around 2^d."""
    half = 1 << (d - 1)       
    r0 = r & ((1 << d) - 1)    
    if r0 > half:
        r0 -= 1 << d           
    r1 = (r - r0) >> d
    return (r1, r0)


def decompose(r: int, alpha: int) -> tuple[int, int]:
    """Decompose *r* into (r1, r0) around the step size *alpha*."""
    
    r0 = r % alpha
    if r0 > alpha // 2:
        r0 -= alpha
    if r - r0 == Q - 1:
        return (0, r0 - 1)
    return ((r - r0) // alpha, r0)


def high_bits(r: int, alpha: int) -> int:
    """Return r1 from decompose(r, alpha) - the high part."""
    return decompose(r, alpha)[0]


def low_bits(r: int, alpha: int) -> int:
    """Return r0 from decompose(r, alpha) - the low part."""
    return decompose(r, alpha)[1]


# ---------------------------------------------------------------------------
# 6. Hint operations
# ---------------------------------------------------------------------------

def make_hint(z: int, r: int, alpha: int) -> int:
    """Compute a 1-bit hint indicating whether adding z changes the high bits."""
    r1 = high_bits(r, alpha)
    v1 = high_bits(mod_pos(r + z), alpha)
    return int(r1 != v1)


def use_hint(h: int, r: int, alpha: int) -> int:
    """Use the 1-bit hint *h* to recover the correct high bits of r + z."""
    m = (Q - 1) // alpha
    r1, r0 = decompose(r, alpha)
    if h == 0:
        return r1
    if r0 > 0:
        return (r1 + 1) % m
    return (r1 - 1) % m
