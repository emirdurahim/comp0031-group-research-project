"""CRYSTALS-Dilithium / ML-DSA (FIPS 204) – placeholder implementation.

Dilithium is a lattice-based digital-signature scheme standardised by
NIST as ML-DSA in FIPS 204.  Three parameter sets are defined, targeting
NIST security levels 2, 3, and 5.

Reference
---------
Ducas et al., "CRYSTALS-Dilithium: A Lattice-Based Digital Signature Scheme",
https://pq-crystals.org/dilithium/
NIST FIPS 204, "Module-Lattice-Based Digital-Signature Standard",
https://csrc.nist.gov/pubs/fips/204/final
"""

from __future__ import annotations

import os
from typing import Dict, List

from .base import KeyPair, SignatureAlgorithm

# ---------------------------------------------------------------------------
# Parameter-set definitions
# ---------------------------------------------------------------------------

# Sizes taken from FIPS 204, Table 1.
_PARAM_SETS: Dict[str, Dict[str, int]] = {
    "ML-DSA-44": {
        "nist_level": 2,
        "public_key_bytes": 1_312,
        "secret_key_bytes": 2_560,
        "signature_bytes": 2_420,
    },
    "ML-DSA-65": {
        "nist_level": 3,
        "public_key_bytes": 1_952,
        "secret_key_bytes": 4_032,
        "signature_bytes": 3_309,
    },
    "ML-DSA-87": {
        "nist_level": 5,
        "public_key_bytes": 2_592,
        "secret_key_bytes": 4_896,
        "signature_bytes": 4_627,
    },
}

PARAMETER_SETS: List[str] = list(_PARAM_SETS.keys())


class Dilithium(SignatureAlgorithm):
    """Placeholder stub for the CRYSTALS-Dilithium / ML-DSA signature scheme.

    The cryptographic operations are **not** implemented; the stub returns
    random bytes of the correct sizes so that the benchmarking framework
    can exercise the full pipeline without real crypto.

    Parameters
    ----------
    parameter_set:
        One of ``"ML-DSA-44"``, ``"ML-DSA-65"``, or ``"ML-DSA-87"``.
    """

    def __init__(self, parameter_set: str = "ML-DSA-44") -> None:
        if parameter_set not in _PARAM_SETS:
            raise ValueError(
                f"Unknown Dilithium parameter set {parameter_set!r}. "
                f"Choose from {list(_PARAM_SETS)}"
            )
        self._parameter_set = parameter_set
        self._params = _PARAM_SETS[parameter_set]

    # ------------------------------------------------------------------
    # SignatureAlgorithm interface
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "Dilithium"

    @property
    def parameter_set(self) -> str:
        return self._parameter_set

    def keygen(self) -> KeyPair:
        """Return a randomly generated (placeholder) key pair."""
        public_key = os.urandom(self._params["public_key_bytes"])
        secret_key = os.urandom(self._params["secret_key_bytes"])
        return KeyPair(public_key=public_key, secret_key=secret_key)

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        """Return a randomly generated (placeholder) signature."""
        return os.urandom(self._params["signature_bytes"])

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Return ``True`` (placeholder – always accepts)."""
        return True
