"""
Algorithm package for PQC KEM implementations.

Exports
-------
KEMAlgorithm           – abstract base class
BIKE                   – BIKE (Bit Flipping Key Encapsulation)
HQC                    – HQC (Hamming Quasi-Cyclic)
ClassicMcEliece        – Classic McEliece
StreamlinedNTRUPrime   – Streamlined NTRU Prime (sntrup)
NTRULPRime             – NTRU LPRime (ntrulpr)

Usage example::

    from src.algorithms import BIKE

    kem = BIKE(parameter_set="Level-1")
    kp  = kem.keygen()
    enc = kem.encapsulate(kp.public_key)
    ss  = kem.decapsulate(enc.ciphertext, kp.secret_key)
"""

from .base import EncapsulationResult, KEMAlgorithm, KeyPair
from .bike import BIKE
from .hqc import HQC
from .mceliece import ClassicMcEliece
from .ntru_lprime import NTRULPRime
from .ntru_prime import StreamlinedNTRUPrime

__all__ = [
    "KEMAlgorithm",
    "KeyPair",
    "EncapsulationResult",
    "BIKE",
    "HQC",
    "ClassicMcEliece",
    "StreamlinedNTRUPrime",
    "NTRULPRime",
]
