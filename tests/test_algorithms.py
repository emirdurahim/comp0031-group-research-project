"""Tests for KEM and signature algorithm interfaces and placeholder implementations."""

from __future__ import annotations

import pytest

from src.algorithms import (
    BIKE,
    HQC,
    ClassicMcEliece,
    Dilithium,
    NTRULPRime,
    StreamlinedNTRUPrime,
)
from src.algorithms.base import EncapsulationResult, KEMAlgorithm, KeyPair, SignatureAlgorithm
from src.algorithms.bike import PARAMETER_SETS as BIKE_PARAM_SETS
from src.algorithms.dilithium import PARAMETER_SETS as DILITHIUM_PARAM_SETS
from src.algorithms.hqc import PARAMETER_SETS as HQC_PARAM_SETS
from src.algorithms.mceliece import PARAMETER_SETS as MCELIECE_PARAM_SETS
from src.algorithms.ntru_lprime import PARAMETER_SETS as NTRULPR_PARAM_SETS
from src.algorithms.ntru_prime import PARAMETER_SETS as SNTRUP_PARAM_SETS


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _check_kem_interface(kem: KEMAlgorithm) -> None:
    """Assert the three core KEM operations work and return the right types."""
    assert isinstance(kem.name, str) and kem.name
    assert isinstance(kem.parameter_set, str) and kem.parameter_set

    kp = kem.keygen()
    assert isinstance(kp, KeyPair)
    assert isinstance(kp.public_key, bytes) and len(kp.public_key) > 0
    assert isinstance(kp.secret_key, bytes) and len(kp.secret_key) > 0

    enc = kem.encapsulate(kp.public_key)
    assert isinstance(enc, EncapsulationResult)
    assert isinstance(enc.ciphertext, bytes) and len(enc.ciphertext) > 0
    assert isinstance(enc.shared_secret, bytes) and len(enc.shared_secret) > 0

    ss = kem.decapsulate(enc.ciphertext, kp.secret_key)
    assert isinstance(ss, bytes) and len(ss) > 0


# ---------------------------------------------------------------------------
# BIKE
# ---------------------------------------------------------------------------

class TestBIKE:
    def test_default_parameter_set(self):
        kem = BIKE()
        assert kem.parameter_set == "Level-1"

    @pytest.mark.parametrize("param_set", BIKE_PARAM_SETS)
    def test_interface(self, param_set):
        _check_kem_interface(BIKE(param_set))

    @pytest.mark.parametrize("param_set", BIKE_PARAM_SETS)
    def test_key_sizes(self, param_set):
        from src.algorithms.bike import _PARAM_SETS
        kem = BIKE(param_set)
        kp = kem.keygen()
        assert len(kp.public_key) == _PARAM_SETS[param_set]["public_key_bytes"]
        assert len(kp.secret_key) == _PARAM_SETS[param_set]["secret_key_bytes"]

    def test_invalid_parameter_set(self):
        with pytest.raises(ValueError, match="Unknown BIKE"):
            BIKE("invalid")

    def test_full_name(self):
        assert BIKE("Level-1").full_name() == "BIKE-Level-1"

    def test_repr(self):
        assert "Level-1" in repr(BIKE("Level-1"))


# ---------------------------------------------------------------------------
# HQC
# ---------------------------------------------------------------------------

class TestHQC:
    def test_default_parameter_set(self):
        assert HQC().parameter_set == "HQC-128"

    @pytest.mark.parametrize("param_set", HQC_PARAM_SETS)
    def test_interface(self, param_set):
        _check_kem_interface(HQC(param_set))

    @pytest.mark.parametrize("param_set", HQC_PARAM_SETS)
    def test_key_sizes(self, param_set):
        from src.algorithms.hqc import _PARAM_SETS
        kem = HQC(param_set)
        kp = kem.keygen()
        assert len(kp.public_key) == _PARAM_SETS[param_set]["public_key_bytes"]

    def test_invalid_parameter_set(self):
        with pytest.raises(ValueError, match="Unknown HQC"):
            HQC("bad")


# ---------------------------------------------------------------------------
# Classic McEliece
# ---------------------------------------------------------------------------

class TestClassicMcEliece:
    def test_default_parameter_set(self):
        assert ClassicMcEliece().parameter_set == "mceliece348864"

    @pytest.mark.parametrize("param_set", MCELIECE_PARAM_SETS)
    def test_interface(self, param_set):
        _check_kem_interface(ClassicMcEliece(param_set))

    def test_invalid_parameter_set(self):
        with pytest.raises(ValueError, match="Unknown Classic McEliece"):
            ClassicMcEliece("bad")


# ---------------------------------------------------------------------------
# Streamlined NTRU Prime
# ---------------------------------------------------------------------------

class TestStreamlinedNTRUPrime:
    def test_default_parameter_set(self):
        assert StreamlinedNTRUPrime().parameter_set == "sntrup761"

    @pytest.mark.parametrize("param_set", SNTRUP_PARAM_SETS)
    def test_interface(self, param_set):
        _check_kem_interface(StreamlinedNTRUPrime(param_set))

    def test_invalid_parameter_set(self):
        with pytest.raises(ValueError, match="Unknown Streamlined NTRU Prime"):
            StreamlinedNTRUPrime("bad")


# ---------------------------------------------------------------------------
# NTRU LPRime
# ---------------------------------------------------------------------------

class TestNTRULPRime:
    def test_default_parameter_set(self):
        assert NTRULPRime().parameter_set == "ntrulpr761"

    @pytest.mark.parametrize("param_set", NTRULPR_PARAM_SETS)
    def test_interface(self, param_set):
        _check_kem_interface(NTRULPRime(param_set))

    def test_invalid_parameter_set(self):
        with pytest.raises(ValueError, match="Unknown NTRU LPRime"):
            NTRULPRime("bad")


# ---------------------------------------------------------------------------
# Abstract base – cannot be instantiated directly
# ---------------------------------------------------------------------------

class TestKEMAlgorithmABC:
    def test_cannot_instantiate_abstract(self):
        with pytest.raises(TypeError):
            KEMAlgorithm()  # type: ignore[abstract]


# ---------------------------------------------------------------------------
# Signature helper
# ---------------------------------------------------------------------------

def _check_signature_interface(sig_alg: SignatureAlgorithm) -> None:
    """Assert the three core signature operations work and return the right types."""
    assert isinstance(sig_alg.name, str) and sig_alg.name
    assert isinstance(sig_alg.parameter_set, str) and sig_alg.parameter_set

    kp = sig_alg.keygen()
    assert isinstance(kp, KeyPair)
    assert isinstance(kp.public_key, bytes) and len(kp.public_key) > 0
    assert isinstance(kp.secret_key, bytes) and len(kp.secret_key) > 0

    message = b"test message"
    sig = sig_alg.sign(kp.secret_key, message)
    assert isinstance(sig, bytes) and len(sig) > 0

    valid = sig_alg.verify(kp.public_key, message, sig)
    assert isinstance(valid, bool)
    assert valid is True


# ---------------------------------------------------------------------------
# Dilithium (FIPS 204 / ML-DSA)
# ---------------------------------------------------------------------------

class TestDilithium:
    def test_default_parameter_set(self):
        assert Dilithium().parameter_set == "ML-DSA-44"

    @pytest.mark.parametrize("param_set", DILITHIUM_PARAM_SETS)
    def test_interface(self, param_set):
        _check_signature_interface(Dilithium(param_set))

    @pytest.mark.parametrize("param_set", DILITHIUM_PARAM_SETS)
    def test_key_sizes(self, param_set):
        from src.algorithms.dilithium import _PARAM_SETS
        alg = Dilithium(param_set)
        kp = alg.keygen()
        assert len(kp.public_key) == _PARAM_SETS[param_set]["public_key_bytes"]
        assert len(kp.secret_key) == _PARAM_SETS[param_set]["secret_key_bytes"]

    @pytest.mark.parametrize("param_set", DILITHIUM_PARAM_SETS)
    def test_signature_size(self, param_set):
        from src.algorithms.dilithium import _PARAM_SETS
        alg = Dilithium(param_set)
        kp = alg.keygen()
        sig = alg.sign(kp.secret_key, b"hello")
        assert len(sig) == _PARAM_SETS[param_set]["signature_bytes"]

    def test_invalid_parameter_set(self):
        with pytest.raises(ValueError, match="Unknown Dilithium"):
            Dilithium("invalid")

    def test_full_name(self):
        assert Dilithium("ML-DSA-44").full_name() == "Dilithium-ML-DSA-44"

    def test_repr(self):
        assert "ML-DSA-44" in repr(Dilithium("ML-DSA-44"))


# ---------------------------------------------------------------------------
# Abstract base – SignatureAlgorithm cannot be instantiated directly
# ---------------------------------------------------------------------------

class TestSignatureAlgorithmABC:
    def test_cannot_instantiate_abstract(self):
        with pytest.raises(TypeError):
            SignatureAlgorithm()  # type: ignore[abstract]
