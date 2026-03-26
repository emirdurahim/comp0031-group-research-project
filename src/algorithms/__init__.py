"""
Algorithm package for PQC implementations.

Exports
-------
KEMAlgorithm           – abstract base class for KEMs
SignatureAlgorithm     – abstract base class for digital signatures
Dilithium              – CRYSTALS-Dilithium / ML-DSA (FIPS 204)
ML_KEM                 – ML-KEM (FIPS 203)
SLH_DSA                – SLH-DSA (FIPS 205)

Usage example (signature)::

    from src.algorithms import Dilithium

    sig_alg = Dilithium(parameter_set="ML-DSA-44")
    kp      = sig_alg.keygen()
    sig     = sig_alg.sign(kp.secret_key, b"hello")
    ok      = sig_alg.verify(kp.public_key, b"hello", sig)
"""

from .base import EncapsulationResult, KEMAlgorithm, KeyPair, SignatureAlgorithm
from .fips204 import ML_DSA
from .fips203 import ML_KEM
from .fips205 import SLH_DSA, PARAMETER_SETS as SLH_DSA_PARAMETER_SETS

__all__ = [
    "KEMAlgorithm",
    "SignatureAlgorithm",
    "KeyPair",
    "EncapsulationResult",
    "ML_DSA",
    "ML_KEM",
    "SLH_DSA",
    "SLH_DSA_PARAMETER_SETS",
]
