"""NTRU LPRime (ntrulpr) – placeholder implementation.

NTRU LPRime is a lattice-based KEM that was a fourth-round candidate in
the NIST Post-Quantum Cryptography standardisation process.  It is one of
the two submissions under the "NTRU Prime" umbrella, alongside Streamlined
NTRU Prime.

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
    "ntrulpr653": {
        "shared_secret_bytes": 32,
        "public_key_bytes": 897,
        "secret_key_bytes": 1_125,
        "ciphertext_bytes": 1_025,
    },
    "ntrulpr761": {
        "shared_secret_bytes": 32,
        "public_key_bytes": 1_039,
        "secret_key_bytes": 1_294,
        "ciphertext_bytes": 1_167,
    },
    "ntrulpr857": {
        "shared_secret_bytes": 32,
        "public_key_bytes": 1_184,
        "secret_key_bytes": 1_463,
        "ciphertext_bytes": 1_312,
    },
    "ntrulpr953": {
        "shared_secret_bytes": 32,
        "public_key_bytes": 1_349,
        "secret_key_bytes": 1_652,
        "ciphertext_bytes": 1_477,
    },
    "ntrulpr1277": {
        "shared_secret_bytes": 32,
        "public_key_bytes": 1_847,
        "secret_key_bytes": 2_231,
        "ciphertext_bytes": 1_975,
    },
}

PARAMETER_SETS: List[str] = list(_PARAM_SETS.keys())


class NTRULPRime(KEMAlgorithm):
    """Placeholder stub for the NTRU LPRime KEM.

    The cryptographic operations are **not** implemented; the stub returns
    random bytes of the correct sizes so that the benchmarking framework
    can exercise the full pipeline without real crypto.

    Parameters
    ----------
    parameter_set:
        One of ``"ntrulpr653"``, ``"ntrulpr761"``, ``"ntrulpr857"``,
        ``"ntrulpr953"``, or ``"ntrulpr1277"``.
    """

    def __init__(self, parameter_set: str = "ntrulpr761") -> None:
        if parameter_set not in _PARAM_SETS:
            raise ValueError(
                f"Unknown NTRU LPRime parameter set {parameter_set!r}. "
                f"Choose from {list(_PARAM_SETS)}"
            )
        self._parameter_set = parameter_set
        self._params = _PARAM_SETS[parameter_set]

    # ------------------------------------------------------------------
    # KEMAlgorithm interface
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "NTRU LPRime"

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
