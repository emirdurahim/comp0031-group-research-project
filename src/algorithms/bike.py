"""BIKE (Bit Flipping Key Encapsulation) – placeholder implementation.

BIKE is a code-based KEM that reached the fourth round of the NIST
Post-Quantum Cryptography standardisation process.  Three parameter
sets are defined, targeting NIST security levels 1, 3, and 5.

Reference
---------
Aragon et al., "BIKE: Bit Flipping Key Encapsulation",
https://bikesuite.org/
"""

from __future__ import annotations

import os
from typing import Dict, List

from .base import EncapsulationResult, KEMAlgorithm, KeyPair

# ---------------------------------------------------------------------------
# Parameter-set definitions
# ---------------------------------------------------------------------------

# Each entry: (r, w, t, shared_secret_bytes, public_key_bytes, ciphertext_bytes)
# Values are taken from the BIKE specification (Round 4 submission).
_PARAM_SETS: Dict[str, Dict[str, int]] = {
    "Level-1": {
        "r": 12_323,
        "w": 142,
        "t": 134,
        "shared_secret_bytes": 32,
        "public_key_bytes": 1_541,
        "secret_key_bytes": 3_110,
        "ciphertext_bytes": 1_573,
    },
    "Level-3": {
        "r": 24_659,
        "w": 206,
        "t": 199,
        "shared_secret_bytes": 32,
        "public_key_bytes": 3_083,
        "secret_key_bytes": 5_788,
        "ciphertext_bytes": 3_115,
    },
    "Level-5": {
        "r": 40_973,
        "w": 274,
        "t": 264,
        "shared_secret_bytes": 32,
        "public_key_bytes": 5_122,
        "secret_key_bytes": 9_720,
        "ciphertext_bytes": 5_154,
    },
}

PARAMETER_SETS: List[str] = list(_PARAM_SETS.keys())


class BIKE(KEMAlgorithm):
    """Placeholder stub for the BIKE KEM.

    The cryptographic operations are **not** implemented; the stub returns
    random bytes of the correct sizes so that the benchmarking framework
    can exercise the full pipeline without real crypto.

    Parameters
    ----------
    parameter_set:
        One of ``"Level-1"``, ``"Level-3"``, or ``"Level-5"``.
    """

    def __init__(self, parameter_set: str = "Level-1") -> None:
        if parameter_set not in _PARAM_SETS:
            raise ValueError(
                f"Unknown BIKE parameter set {parameter_set!r}. "
                f"Choose from {list(_PARAM_SETS)}"
            )
        self._parameter_set = parameter_set
        self._params = _PARAM_SETS[parameter_set]

    # ------------------------------------------------------------------
    # KEMAlgorithm interface
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "BIKE"

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
