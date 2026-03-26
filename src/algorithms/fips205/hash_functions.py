"""FIPS 205 (SLH-DSA) — Tweakable hash function instantiations (SHAKE only).

Implements the 6 core hash functions: H_msg, PRF, PRF_msg, F, H, T_l.
All use SHAKE-256 as the underlying XOF (FIPS 205 Section 11.1).

Reference
---------
NIST FIPS 205, Section 11.1 — "Instantiation with SHAKE".
"""

from __future__ import annotations

import hashlib
from .address import ADRS

# -----------------------------------------------------------------------------
# SHAKE-256 wrapper
# -----------------------------------------------------------------------------

def _shake256_hash(data: bytes, out_len: int) -> bytes:
    """Helper for SHAKE-256 Extendable-Output Function."""
    return hashlib.shake_256(data).digest(out_len)

# -----------------------------------------------------------------------------
# Tweakable hash functions
# -----------------------------------------------------------------------------

def H_msg(R: bytes, pk_seed: bytes, pk_root: bytes, m: bytes, n: int) -> bytes:
    """Message hash: SHAKE256(R || pk_seed || pk_root || m, out_len=m_bytes).
    Note: 'n' parameter here refers to the message digest output length 'm'
    from the parameter set, not the security parameter 'n'.
    """
    return _shake256_hash(R + pk_seed + pk_root + m, n)


def PRF(pk_seed: bytes, sk_seed: bytes, adrs: ADRS, n: int) -> bytes:
    """Pseudorandom function: SHAKE256(pk_seed || ADRS || sk_seed, out_len=n)."""
    return _shake256_hash(pk_seed + adrs.to_bytes() + sk_seed, n)


def PRF_msg(sk_prf: bytes, opt_rand: bytes, m: bytes, n: int) -> bytes:
    """Message PRF: SHAKE256(sk_prf || opt_rand || m, out_len=n)."""
    return _shake256_hash(sk_prf + opt_rand + m, n)


# For SHAKE-based variants, F, H, and T_l are identical functions differing
# only by input length and semantics (which is handled by ADRS and input bytes).

def F(pk_seed: bytes, adrs: ADRS, m1: bytes, n: int) -> bytes:
    """Tweakable hash for short inputs: SHAKE256(pk_seed || ADRS || m1, out_len=n)."""
    return _shake256_hash(pk_seed + adrs.to_bytes() + m1, n)


def H(pk_seed: bytes, adrs: ADRS, m2: bytes, n: int) -> bytes:
    """Tweakable hash for node pairs: SHAKE256(pk_seed || ADRS || m2, out_len=n)."""
    return _shake256_hash(pk_seed + adrs.to_bytes() + m2, n)


def T_l(pk_seed: bytes, adrs: ADRS, ml: bytes, n: int) -> bytes:
    """Tweakable hash for long inputs: SHAKE256(pk_seed || ADRS || ml, out_len=n)."""
    return _shake256_hash(pk_seed + adrs.to_bytes() + ml, n)
