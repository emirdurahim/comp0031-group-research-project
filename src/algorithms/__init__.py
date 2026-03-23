"""
Algorithm package for PQC implementations.

Exports
-------
KEMAlgorithm           – abstract base class for KEMs
SignatureAlgorithm     – abstract base class for digital signatures
BIKE                   – BIKE (Bit Flipping Key Encapsulation)
HQC                    – HQC (Hamming Quasi-Cyclic)
ClassicMcEliece        – Classic McEliece
StreamlinedNTRUPrime   – Streamlined NTRU Prime (sntrup)
NTRULPRime             – NTRU LPRime (ntrulpr)
Dilithium              – CRYSTALS-Dilithium / ML-DSA (FIPS 204)

Usage example (KEM)::

    from src.algorithms import BIKE

    kem = BIKE(parameter_set="Level-1")
    kp  = kem.keygen()
    enc = kem.encapsulate(kp.public_key)
    ss  = kem.decapsulate(enc.ciphertext, kp.secret_key)

Usage example (signature)::

    from src.algorithms import Dilithium

    sig_alg = Dilithium(parameter_set="ML-DSA-44")
    kp      = sig_alg.keygen()
    sig     = sig_alg.sign(kp.secret_key, b"hello")
    ok      = sig_alg.verify(kp.public_key, b"hello", sig)
"""

from .base import EncapsulationResult, KEMAlgorithm, KeyPair, SignatureAlgorithm
from .bike import BIKE
from .dilithium import Dilithium
from .hqc import HQC
from .mceliece import ClassicMcEliece
from .ntru_lprime import NTRULPRime
from .ntru_prime import StreamlinedNTRUPrime
from .fips203 import ML_KEM

__all__ = [
    "KEMAlgorithm",
    "SignatureAlgorithm",
    "KeyPair",
    "EncapsulationResult",
    "BIKE",
    "HQC",
    "ClassicMcEliece",
    "StreamlinedNTRUPrime",
    "NTRULPRime",
    "Dilithium",
    "ML_KEM",
]
