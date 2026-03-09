"""Streamlined NTRU Prime (sntrup) – placeholder implementation.

Streamlined NTRU Prime is a lattice/code-based KEM that was a fourth-round
candidate in the NIST Post-Quantum Cryptography standardisation process.
It is one of the two submissions under the "NTRU Prime" umbrella.

Reference
---------
Bernstein et al., "NTRU Prime",
https://ntruprime.cr.yp.to/
"""

from __future__ import annotations

import os
from typing import Dict, List

from .base import EncapsulationResult, KEMAlgorithm, KeyPair

# ---------------------------------------------------------------------------
# Parameter-set definitions
# ---------------------------------------------------------------------------

# Sizes taken from the NTRU Prime Round 4 specification.
_PARAM_SETS: Dict[str, Dict[str, int]] = {
    "sntrup653": {
        "shared_secret_bytes": 32,
        "public_key_bytes": 994,
        "secret_key_bytes": 1_518,
        "ciphertext_bytes": 897,
    },
    "sntrup761": {
        "shared_secret_bytes": 32,
        "public_key_bytes": 1_158,
        "secret_key_bytes": 1_763,
        "ciphertext_bytes": 1_039,
    },
    "sntrup857": {
        "shared_secret_bytes": 32,
        "public_key_bytes": 1_322,
        "secret_key_bytes": 1_999,
        "ciphertext_bytes": 1_184,
    },
    "sntrup953": {
        "shared_secret_bytes": 32,
        "public_key_bytes": 1_505,
        "secret_key_bytes": 2_254,
        "ciphertext_bytes": 1_349,
    },
    "sntrup1277": {
        "shared_secret_bytes": 32,
        "public_key_bytes": 2_067,
        "secret_key_bytes": 3_059,
        "ciphertext_bytes": 1_847,
    },
}

PARAMETER_SETS: List[str] = list(_PARAM_SETS.keys())


class StreamlinedNTRUPrime(KEMAlgorithm):
    """Placeholder stub for the Streamlined NTRU Prime KEM.

    The cryptographic operations are **not** implemented; the stub returns
    random bytes of the correct sizes so that the benchmarking framework
    can exercise the full pipeline without real crypto.

    Parameters
    ----------
    parameter_set:
        One of ``"sntrup653"``, ``"sntrup761"``, ``"sntrup857"``,
        ``"sntrup953"``, or ``"sntrup1277"``.
    """

    def __init__(self, parameter_set: str = "sntrup761") -> None:
        if parameter_set not in _PARAM_SETS:
            raise ValueError(
                f"Unknown Streamlined NTRU Prime parameter set {parameter_set!r}. "
                f"Choose from {list(_PARAM_SETS)}"
            )
        self._parameter_set = parameter_set
        self._params = _PARAM_SETS[parameter_set]

    # ------------------------------------------------------------------
    # KEMAlgorithm interface
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "Streamlined NTRU Prime"

    @property
    def parameter_set(self) -> str:
        return self._parameter_set

    def keygen(self) -> KeyPair:
        """Return a randomly generated (placeholder) key pair."""
        public_key = os.urandom(self._params["public_key_bytes"])
        secret_key = os.urandom(self._params["secret_key_bytes"])
        return KeyPair(public_key=public_key, secret_key=secret_key)

    def encapsulate(self, public_key: bytes) -> EncapsulationResult:
        """Return a randomly generated (placeholder) ciphertext and shared secret."""
        ciphertext = os.urandom(self._params["ciphertext_bytes"])
        shared_secret = os.urandom(self._params["shared_secret_bytes"])
        return EncapsulationResult(ciphertext=ciphertext, shared_secret=shared_secret)

    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """Return a randomly generated (placeholder) shared secret."""
        return os.urandom(self._params["shared_secret_bytes"])
