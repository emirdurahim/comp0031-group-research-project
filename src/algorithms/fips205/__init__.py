"""FIPS 205 (SLH-DSA) — Stateless Hash-Based Digital Signature Algorithm.

Public API wrapping the internal SLH-DSA operations into the framework's
``SignatureAlgorithm`` interface. Implements FIPS 205 Algorithms 21-24
(pure SLH-DSA mode, SHAKE-based parameter sets only).

Exports
-------
SLH_DSA          — SignatureAlgorithm subclass for SLH-DSA
PARAMETER_SETS   — list of supported parameter set names

Usage example::

    from src.algorithms.fips205 import SLH_DSA

    sig_alg = SLH_DSA(parameter_set="SLH-DSA-SHAKE-128f")
    kp      = sig_alg.keygen()
    sig     = sig_alg.sign(kp.secret_key, b"hello")
    ok      = sig_alg.verify(kp.public_key, b"hello", sig)

Reference
---------
NIST FIPS 205, "Stateless Hash-Based Digital Signature Standard".
https://csrc.nist.gov/pubs/fips/205/final
"""

from __future__ import annotations

import os

from ..base import KeyPair, SignatureAlgorithm
from .core import slh_keygen_internal, slh_sign_internal, slh_verify_internal
from .parameters import PARAMETER_SETS, get_params


class SLH_DSA(SignatureAlgorithm):
    """FIPS 205 Stateless Hash-Based Digital Signature Algorithm."""

    def __init__(self, parameter_set: str = "SLH-DSA-SHAKE-128s") -> None:
        if parameter_set not in PARAMETER_SETS:
            raise ValueError(
                f"Unknown SLH-DSA parameter set {parameter_set!r}. "
                f"Choose from {PARAMETER_SETS}"
            )
        self._parameter_set = parameter_set
        self._params = get_params(parameter_set)

    @property
    def name(self) -> str:
        return "SLH-DSA"

    @property
    def parameter_set(self) -> str:
        return self._parameter_set

    def keygen(self) -> KeyPair:
        """Algorithm 21: Generate a key pair.
        
        Uses os.urandom for seeds and delegates to slh_keygen_internal.
        """
        n = self._params.n
        sk_seed = os.urandom(n)
        sk_prf = os.urandom(n)
        pk_seed = os.urandom(n)
        
        sk, pk = slh_keygen_internal(sk_seed, sk_prf, pk_seed, self._params)
        return KeyPair(public_key=pk, secret_key=sk)

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        """Algorithm 22: Sign a message (pure SLH-DSA mode).
        
        Prepends the domain separator (0x00, 0x00) to the message.
        """
        # Domain separation for pure mode: domain (0x00) || context_len (0x00)
        M_internal = b'\x00\x00' + message
        
        # We default to using randomizer if os.urandom is available
        addrnd = os.urandom(self._params.n)
        
        return slh_sign_internal(M_internal, secret_key, self._params, addrnd)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Algorithm 24: Verify a signature (pure SLH-DSA mode).
        
        Prepends the same domain separator to the message.
        """
        M_internal = b'\x00\x00' + message
        return slh_verify_internal(M_internal, signature, public_key, self._params)

__all__ = ["SLH_DSA", "PARAMETER_SETS"]
