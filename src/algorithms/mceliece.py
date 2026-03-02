"""Classic McEliece – placeholder implementation.

Classic McEliece is a code-based KEM based on the McEliece cryptosystem
(1978).  It was a finalist in the NIST Post-Quantum Cryptography
standardisation process (Rounds 3 and 4).  Five parameter sets are
defined.

Reference
---------
Bernstein et al., "Classic McEliece",
https://classic.mceliece.org/
"""

from __future__ import annotations

import os
from typing import Dict, List

from .base import EncapsulationResult, KEMAlgorithm, KeyPair

# ---------------------------------------------------------------------------
# Parameter-set definitions
# ---------------------------------------------------------------------------

# Sizes taken from the Classic McEliece Round 4 specification.
_PARAM_SETS: Dict[str, Dict[str, int]] = {
    "mceliece348864": {
        "shared_secret_bytes": 32,
        "public_key_bytes": 261_120,
        "secret_key_bytes": 6_492,
        "ciphertext_bytes": 128,
    },
    "mceliece460896": {
        "shared_secret_bytes": 32,
        "public_key_bytes": 524_160,
        "secret_key_bytes": 13_608,
        "ciphertext_bytes": 188,
    },
    "mceliece6688128": {
        "shared_secret_bytes": 32,
        "public_key_bytes": 1_044_992,
        "secret_key_bytes": 13_932,
        "ciphertext_bytes": 240,
    },
    "mceliece6960119": {
        "shared_secret_bytes": 32,
        "public_key_bytes": 1_047_319,
        "secret_key_bytes": 13_948,
        "ciphertext_bytes": 226,
    },
    "mceliece8192128": {
        "shared_secret_bytes": 32,
        "public_key_bytes": 1_357_824,
        "secret_key_bytes": 14_120,
        "ciphertext_bytes": 240,
    },
}

PARAMETER_SETS: List[str] = list(_PARAM_SETS.keys())


class ClassicMcEliece(KEMAlgorithm):
    """Placeholder stub for the Classic McEliece KEM.

    The cryptographic operations are **not** implemented; the stub returns
    random bytes of the correct sizes so that the benchmarking framework
    can exercise the full pipeline without real crypto.

    Parameters
    ----------
    parameter_set:
        One of ``"mceliece348864"``, ``"mceliece460896"``,
        ``"mceliece6688128"``, ``"mceliece6960119"``, or
        ``"mceliece8192128"``.
    """

    def __init__(self, parameter_set: str = "mceliece348864") -> None:
        if parameter_set not in _PARAM_SETS:
            raise ValueError(
                f"Unknown Classic McEliece parameter set {parameter_set!r}. "
                f"Choose from {list(_PARAM_SETS)}"
            )
        self._parameter_set = parameter_set
        self._params = _PARAM_SETS[parameter_set]

    # ------------------------------------------------------------------
    # KEMAlgorithm interface
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "Classic McEliece"

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
