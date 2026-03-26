"""FIPS 205 (SLH-DSA) — Parameter set definitions.

Defines the 6 SHAKE-based parameter sets from FIPS 205 Table 2.
SHA2-based parameter sets are excluded.

Each parameter set is a frozen dataclass containing the raw parameters
from Table 2 and the derived WOTS+ constants (w, len1, len2, len).

Reference
---------
NIST FIPS 205, Table 2 — "SLH-DSA parameter sets".
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Dict, List

@dataclass(frozen=True)
class SLHDSAParameters:
    """FIPS 205 SLH-DSA parameter set constants."""
    name: str

    # Table 2 raw parameters
    n: int
    h: int
    d: int
    hp: int
    a: int
    k: int
    lg_w: int
    m: int

    # Derived WOTS+ constants
    w: int
    len1: int
    len2: int
    length: int

    # Size constants for metrics and testing
    pk_bytes: int
    sk_bytes: int
    sig_bytes: int

    @classmethod
    def create(cls, name: str, n: int, h: int, d: int, a: int, k: int, m: int) -> SLHDSAParameters:
        """Instantiate parameters from Table 2 values, computing derived constants."""
        lg_w = 4
        w = 1 << lg_w
        hp = h // d
        
        # Eq 5.1, 5.2
        len1 = math.ceil(8 * n / lg_w)
        
        # Eq 5.3, 5.4
        len2 = math.floor(math.log(len1 * (w - 1)) / math.log(w)) + 1
        
        length = len1 + len2
        
        pk_bytes = 2 * n
        sk_bytes = 4 * n
        sig_bytes = n + k * (1 + a) * n + (h + d * length) * n

        return cls(
            name=name,
            n=n, h=h, d=d, hp=hp, a=a, k=k, lg_w=lg_w, m=m,
            w=w, len1=len1, len2=len2, length=length,
            pk_bytes=pk_bytes, sk_bytes=sk_bytes, sig_bytes=sig_bytes
        )

# Define the 6 SHAKE-based parameter sets (FIPS 205 Table 2)
_PARAM_SETS: Dict[str, SLHDSAParameters] = {
    "SLH-DSA-SHAKE-128s": SLHDSAParameters.create("SLH-DSA-SHAKE-128s", 16, 63, 7, 12, 14, 30),
    "SLH-DSA-SHAKE-128f": SLHDSAParameters.create("SLH-DSA-SHAKE-128f", 16, 66, 22, 6, 33, 34),
    "SLH-DSA-SHAKE-192s": SLHDSAParameters.create("SLH-DSA-SHAKE-192s", 24, 63, 7, 14, 17, 39),
    "SLH-DSA-SHAKE-192f": SLHDSAParameters.create("SLH-DSA-SHAKE-192f", 24, 66, 22, 8, 33, 42),
    "SLH-DSA-SHAKE-256s": SLHDSAParameters.create("SLH-DSA-SHAKE-256s", 32, 64, 8, 14, 22, 47),
    "SLH-DSA-SHAKE-256f": SLHDSAParameters.create("SLH-DSA-SHAKE-256f", 32, 68, 17, 9, 35, 49),
}

PARAMETER_SETS: List[str] = list(_PARAM_SETS.keys())

def get_params(name: str) -> SLHDSAParameters:
    """Return the parameter set definitions for the given name."""
    if name not in _PARAM_SETS:
        raise ValueError(f"Unknown SLH-DSA parameter set {name!r}.")
    return _PARAM_SETS[name]
