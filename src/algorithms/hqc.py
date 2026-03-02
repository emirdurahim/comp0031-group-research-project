"""HQC (Hamming Quasi-Cyclic) – placeholder implementation.

HQC is a code-based KEM that reached the fourth round of the NIST
Post-Quantum Cryptography standardisation process.  Three parameter
sets target NIST security levels 1, 3, and 5.

Reference
---------
Melchor et al., "HQC: Hamming Quasi-Cyclic",
https://pqc-hqc.org/
"""

from __future__ import annotations

import os
from typing import Dict, List

from .base import EncapsulationResult, KEMAlgorithm, KeyPair

# ---------------------------------------------------------------------------
# Parameter-set definitions
# ---------------------------------------------------------------------------

# Sizes taken from the HQC Round 4 specification document.
_PARAM_SETS: Dict[str, Dict[str, int]] = {
    "HQC-128": {
        "n": 17_669,
        "shared_secret_bytes": 64,
        "public_key_bytes": 2_249,
        "secret_key_bytes": 2_289,
        "ciphertext_bytes": 4_481,
    },
    "HQC-192": {
        "n": 35_851,
        "shared_secret_bytes": 64,
        "public_key_bytes": 4_522,
        "secret_key_bytes": 4_562,
        "ciphertext_bytes": 9_026,
    },
    "HQC-256": {
        "n": 57_637,
        "shared_secret_bytes": 64,
        "public_key_bytes": 7_245,
        "secret_key_bytes": 7_285,
        "ciphertext_bytes": 14_469,
    },
}

PARAMETER_SETS: List[str] = list(_PARAM_SETS.keys())


class HQC(KEMAlgorithm):
    """Placeholder stub for the HQC KEM.

    The cryptographic operations are **not** implemented; the stub returns
    random bytes of the correct sizes so that the benchmarking framework
    can exercise the full pipeline without real crypto.

    Parameters
    ----------
    parameter_set:
        One of ``"HQC-128"``, ``"HQC-192"``, or ``"HQC-256"``.
    """

    def __init__(self, parameter_set: str = "HQC-128") -> None:
        if parameter_set not in _PARAM_SETS:
            raise ValueError(
                f"Unknown HQC parameter set {parameter_set!r}. "
                f"Choose from {list(_PARAM_SETS)}"
            )
        self._parameter_set = parameter_set
        self._params = _PARAM_SETS[parameter_set]

    # ------------------------------------------------------------------
    # KEMAlgorithm interface
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "HQC"

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
