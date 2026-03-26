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

from ..base import KeyPair, SignatureAlgorithm
from .core import ml_dsa_keygen, ml_dsa_sign, ml_dsa_verify

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


class ML_DSA(SignatureAlgorithm):

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
        pk, sk = ml_dsa_keygen(self._parameter_set)
        return KeyPair(public_key=pk, secret_key=sk)

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        return ml_dsa_sign(secret_key, message, self._parameter_set)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        return ml_dsa_verify(public_key, message, signature, self._parameter_set)
