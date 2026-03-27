"""Tests for FIPS 204 (ML-DSA) encoding / decoding layer."""

from __future__ import annotations

import os

import pytest

from src.algorithms.fips204.math import Q, N, D, Poly
from src.algorithms.fips204.encoding import (
    _bit_pack, _bit_unpack,
    _simple_bit_pack, _simple_bit_unpack,
    pk_encode, pk_decode,
    sk_encode, sk_decode,
    sig_encode, sig_decode,
    w1_encode,
)


# ---------------------------------------------------------------------------
# Generic bit-pack / bit-unpack
# ---------------------------------------------------------------------------

class TestBitPack:
    @pytest.mark.parametrize("eta", [2, 4])
    def test_roundtrip(self, eta):
        """Pack then unpack should recover the original polynomial."""
        import random
        rng = random.Random(123)
        poly = [rng.randint(-eta, eta) for _ in range(N)]
        data = _bit_pack(poly, eta, eta)
        recovered = _bit_unpack(data, eta, eta)
        assert recovered == poly

    def test_zero_poly(self):
        poly = [0] * N
        data = _bit_pack(poly, 2, 2)
        assert _bit_unpack(data, 2, 2) == poly


# ---------------------------------------------------------------------------
# Simple bit-pack / unpack (unsigned)
# ---------------------------------------------------------------------------

class TestSimpleBitPack:
    def test_roundtrip_t1(self):
        """t1 coefficients are in [0, 2^10 - 1]."""
        import random
        rng = random.Random(456)
        bound = (1 << 10) - 1
        poly = [rng.randint(0, bound) for _ in range(N)]
        data = _simple_bit_pack(poly, bound)
        recovered = _simple_bit_unpack(data, bound)
        assert recovered == poly

    def test_byte_length_t1(self):
        """256 coefficients * 10 bits = 320 bytes."""
        bound = (1 << 10) - 1
        poly = [0] * N
        data = _simple_bit_pack(poly, bound)
        assert len(data) == 320


# ---------------------------------------------------------------------------
# Public key encode / decode
# ---------------------------------------------------------------------------

class TestPKEncodeDecode:
    @pytest.mark.parametrize("k", [4, 6, 8])
    def test_roundtrip(self, k):
        import random
        rng = random.Random(789)
        rho = os.urandom(32)
        bound = (1 << 10) - 1
        t1 = [[rng.randint(0, bound) for _ in range(N)] for _ in range(k)]
        pk = pk_encode(rho, t1)
        rho_out, t1_out = pk_decode(pk, k)
        assert rho_out == rho
        assert t1_out == t1

    @pytest.mark.parametrize("k,expected_bytes", [(4, 1312), (6, 1952), (8, 2592)])
    def test_pk_size(self, k, expected_bytes):
        rho = b'\x00' * 32
        t1 = [[0] * N for _ in range(k)]
        pk = pk_encode(rho, t1)
        assert len(pk) == expected_bytes


# ---------------------------------------------------------------------------
# Secret key encode / decode
# ---------------------------------------------------------------------------

class TestSKEncodeDecode:
    @pytest.mark.parametrize("k,l,eta", [(4, 4, 2), (6, 5, 4), (8, 7, 2)])
    def test_roundtrip(self, k, l, eta):
        import random
        rng = random.Random(101)
        rho = os.urandom(32)
        K = os.urandom(32)
        tr = os.urandom(64)
        s1 = [[rng.randint(-eta, eta) for _ in range(N)] for _ in range(l)]
        s2 = [[rng.randint(-eta, eta) for _ in range(N)] for _ in range(k)]
        t0_upper = 1 << (D - 1)
        t0 = [[rng.randint(-(t0_upper - 1), t0_upper) for _ in range(N)] for _ in range(k)]
        sk = sk_encode(rho, K, tr, s1, s2, t0, eta)
        rho_out, K_out, tr_out, s1_out, s2_out, t0_out = sk_decode(sk, k, l, eta)
        assert rho_out == rho
        assert K_out == K
        assert tr_out == tr
        assert s1_out == s1
        assert s2_out == s2
        assert t0_out == t0

    @pytest.mark.parametrize("k,l,eta,expected_bytes", [
        (4, 4, 2, 2560),
        (6, 5, 4, 4032),
        (8, 7, 2, 4896),
    ])
    def test_sk_size(self, k, l, eta, expected_bytes):
        rho = b'\x00' * 32
        K = b'\x00' * 32
        tr = b'\x00' * 64
        s1 = [[0] * N for _ in range(l)]
        s2 = [[0] * N for _ in range(k)]
        t0 = [[0] * N for _ in range(k)]
        sk = sk_encode(rho, K, tr, s1, s2, t0, eta)
        assert len(sk) == expected_bytes


# ---------------------------------------------------------------------------
# Signature encode / decode
# ---------------------------------------------------------------------------

class TestSigEncodeDecode:
    @pytest.mark.parametrize("k,l,gamma1,omega,ctilde_len", [
        (4, 4, 1 << 17, 80, 32),   # ML-DSA-44
        (6, 5, 1 << 19, 55, 48),   # ML-DSA-65
        (8, 7, 1 << 19, 75, 64),   # ML-DSA-87
    ])
    def test_roundtrip(self, k, l, gamma1, omega, ctilde_len):
        import random
        rng = random.Random(202)
        ctilde = os.urandom(ctilde_len)
        z = [[rng.randint(-(gamma1 - 1), gamma1) for _ in range(N)] for _ in range(l)]
        # Build a valid hint: a few random positions per polynomial
        h = []
        for i in range(k):
            positions = sorted(rng.sample(range(N), rng.randint(0, 3)))
            h.append(positions)
        sig = sig_encode(ctilde, z, h, gamma1, omega, k)
        result = sig_decode(sig, l, k, gamma1, omega, ctilde_len)
        assert result is not None
        ctilde_out, z_out, h_out = result
        assert ctilde_out == ctilde
        assert z_out == z
        assert h_out == h

    @pytest.mark.parametrize("k,l,gamma1,omega,ctilde_len,expected", [
        (4, 4, 1 << 17, 80, 32,  2420),  # ML-DSA-44
        (6, 5, 1 << 19, 55, 48,  3309),  # ML-DSA-65
        (8, 7, 1 << 19, 75, 64,  4627),  # ML-DSA-87
    ])
    def test_signature_size(self, k, l, gamma1, omega, ctilde_len, expected):
        ctilde = b'\x00' * ctilde_len
        z = [[0] * N for _ in range(l)]
        h = [[] for _ in range(k)]
        sig = sig_encode(ctilde, z, h, gamma1, omega, k)
        assert len(sig) == expected


# ---------------------------------------------------------------------------
# w1_encode
# ---------------------------------------------------------------------------

class TestW1Encode:
    @pytest.mark.parametrize("gamma2,k", [(95_232, 4), (261_888, 6)])
    def test_produces_bytes(self, gamma2, k):
        m = (Q - 1) // (2 * gamma2)
        w1 = [[0] * N for _ in range(k)]
        result = w1_encode(w1, gamma2)
        assert isinstance(result, bytes)
        assert len(result) > 0
