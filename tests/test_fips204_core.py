"""Tests for FIPS 204 (ML-DSA) core keygen / sign / verify layer."""

from __future__ import annotations

import os

import pytest

from src.algorithms.fips204.core import (
    _PARAMS,
    ml_dsa_keygen,
    ml_dsa_sign,
    ml_dsa_verify,
)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

_FAST_PARAM = "ML-DSA-44"  # smallest / fastest parameter set


# ---------------------------------------------------------------------------
# KeyGen
# ---------------------------------------------------------------------------

class TestKeyGen:
    def test_returns_pk_sk_bytes(self):
        pk, sk = ml_dsa_keygen(_FAST_PARAM)
        assert isinstance(pk, bytes)
        assert isinstance(sk, bytes)

    @pytest.mark.parametrize("param_set", list(_PARAMS.keys()))
    def test_key_sizes(self, param_set):
        """Public and secret keys must match the sizes in FIPS 204 Table 1."""
        from src.algorithms.fips204 import _PARAM_SETS
        pk, sk = ml_dsa_keygen(param_set)
        assert len(pk) == _PARAM_SETS[param_set]["public_key_bytes"]
        assert len(sk) == _PARAM_SETS[param_set]["secret_key_bytes"]

    def test_different_calls_produce_different_keys(self):
        pk1, sk1 = ml_dsa_keygen(_FAST_PARAM)
        pk2, sk2 = ml_dsa_keygen(_FAST_PARAM)
        assert pk1 != pk2 or sk1 != sk2


# ---------------------------------------------------------------------------
# Sign / Verify round-trip
# ---------------------------------------------------------------------------

class TestSignVerify:
    def test_sign_verify_cycle(self):
        pk, sk = ml_dsa_keygen(_FAST_PARAM)
        msg = b"Hello FIPS 204!"
        sig = ml_dsa_sign(sk, msg, _FAST_PARAM)
        assert isinstance(sig, bytes)
        assert ml_dsa_verify(pk, msg, sig, _FAST_PARAM) is True

    @pytest.mark.parametrize("param_set", list(_PARAMS.keys()))
    def test_signature_size(self, param_set):
        from src.algorithms.fips204 import _PARAM_SETS
        pk, sk = ml_dsa_keygen(param_set)
        sig = ml_dsa_sign(sk, b"size check", param_set)
        assert len(sig) == _PARAM_SETS[param_set]["signature_bytes"]

    def test_wrong_message_fails(self):
        pk, sk = ml_dsa_keygen(_FAST_PARAM)
        sig = ml_dsa_sign(sk, b"correct message", _FAST_PARAM)
        assert ml_dsa_verify(pk, b"wrong message", sig, _FAST_PARAM) is False

    def test_tampered_signature_fails(self):
        pk, sk = ml_dsa_keygen(_FAST_PARAM)
        sig = ml_dsa_sign(sk, b"tamper test", _FAST_PARAM)
        tampered = bytearray(sig)
        tampered[0] ^= 0xFF
        assert ml_dsa_verify(pk, b"tamper test", bytes(tampered), _FAST_PARAM) is False

    def test_empty_message(self):
        pk, sk = ml_dsa_keygen(_FAST_PARAM)
        sig = ml_dsa_sign(sk, b"", _FAST_PARAM)
        assert ml_dsa_verify(pk, b"", sig, _FAST_PARAM) is True

    def test_long_message(self):
        pk, sk = ml_dsa_keygen(_FAST_PARAM)
        msg = os.urandom(10_000)
        sig = ml_dsa_sign(sk, msg, _FAST_PARAM)
        assert ml_dsa_verify(pk, msg, sig, _FAST_PARAM) is True

    def test_wrong_pk_fails(self):
        pk1, sk1 = ml_dsa_keygen(_FAST_PARAM)
        pk2, sk2 = ml_dsa_keygen(_FAST_PARAM)
        sig = ml_dsa_sign(sk1, b"cross key", _FAST_PARAM)
        assert ml_dsa_verify(pk2, b"cross key", sig, _FAST_PARAM) is False
