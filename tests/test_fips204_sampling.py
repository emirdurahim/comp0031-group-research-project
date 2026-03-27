"""Tests for FIPS 204 (ML-DSA) sampling layer."""

from __future__ import annotations

import os

import pytest

from src.algorithms.fips204.math import Q, N, Poly
from src.algorithms.fips204.sampling import (
    rej_ntt_poly,
    rej_bounded_poly,
    expand_a,
    expand_s,
    expand_mask,
    sample_in_ball,
)


# ---------------------------------------------------------------------------
# rej_ntt_poly
# ---------------------------------------------------------------------------

class TestRejNTTPoly:
    def test_length(self):
        seed = os.urandom(34)  # rho (32) + two index bytes
        poly = rej_ntt_poly(seed)
        assert len(poly) == N

    def test_coefficients_in_range(self):
        seed = os.urandom(34)
        poly = rej_ntt_poly(seed)
        for c in poly:
            assert 0 <= c < Q

    def test_deterministic(self):
        seed = b'\x00' * 34
        assert rej_ntt_poly(seed) == rej_ntt_poly(seed)


# ---------------------------------------------------------------------------
# rej_bounded_poly
# ---------------------------------------------------------------------------

class TestRejBoundedPoly:
    @pytest.mark.parametrize("eta", [2, 4])
    def test_length(self, eta):
        seed = os.urandom(66)
        poly = rej_bounded_poly(seed, eta)
        assert len(poly) == N

    @pytest.mark.parametrize("eta", [2, 4])
    def test_coefficients_in_range(self, eta):
        seed = os.urandom(66)
        poly = rej_bounded_poly(seed, eta)
        for c in poly:
            assert -eta <= c <= eta

    def test_deterministic(self):
        seed = b'\x01' * 66
        assert rej_bounded_poly(seed, 2) == rej_bounded_poly(seed, 2)


# ---------------------------------------------------------------------------
# expand_a
# ---------------------------------------------------------------------------

class TestExpandA:
    @pytest.mark.parametrize("k,l", [(4, 4), (6, 5), (8, 7)])
    def test_matrix_dimensions(self, k, l):
        rho = os.urandom(32)
        A = expand_a(rho, k, l)
        assert len(A) == k
        for row in A:
            assert len(row) == l
            for poly in row:
                assert len(poly) == N

    def test_coefficients_in_range(self):
        rho = os.urandom(32)
        A = expand_a(rho, 4, 4)
        for row in A:
            for poly in row:
                for c in poly:
                    assert 0 <= c < Q

    def test_deterministic(self):
        rho = b'\xAB' * 32
        A1 = expand_a(rho, 4, 4)
        A2 = expand_a(rho, 4, 4)
        assert A1 == A2


# ---------------------------------------------------------------------------
# expand_s
# ---------------------------------------------------------------------------

class TestExpandS:
    @pytest.mark.parametrize("k,l,eta", [(4, 4, 2), (6, 5, 4), (8, 7, 2)])
    def test_vector_lengths(self, k, l, eta):
        rhoprime = os.urandom(64)
        s1, s2 = expand_s(rhoprime, k, l, eta)
        assert len(s1) == l
        assert len(s2) == k

    @pytest.mark.parametrize("eta", [2, 4])
    def test_coefficient_bounds(self, eta):
        rhoprime = os.urandom(64)
        s1, s2 = expand_s(rhoprime, 4, 4, eta)
        for vec in (s1, s2):
            for poly in vec:
                for c in poly:
                    assert -eta <= c <= eta


# ---------------------------------------------------------------------------
# expand_mask
# ---------------------------------------------------------------------------

class TestExpandMask:
    @pytest.mark.parametrize("gamma1", [1 << 17, 1 << 19])
    def test_vector_length(self, gamma1):
        rhoprime = os.urandom(64)
        y = expand_mask(rhoprime, 0, 4, gamma1)
        assert len(y) == 4
        for poly in y:
            assert len(poly) == N

    @pytest.mark.parametrize("gamma1", [1 << 17, 1 << 19])
    def test_coefficient_bounds(self, gamma1):
        rhoprime = os.urandom(64)
        y = expand_mask(rhoprime, 0, 4, gamma1)
        for poly in y:
            for c in poly:
                assert -(gamma1 - 1) <= c <= gamma1


# ---------------------------------------------------------------------------
# sample_in_ball
# ---------------------------------------------------------------------------

class TestSampleInBall:
    @pytest.mark.parametrize("tau", [39, 49, 60])
    def test_sparsity(self, tau):
        """Exactly tau non-zero coefficients."""
        ctilde = os.urandom(32)
        c = sample_in_ball(ctilde, tau)
        assert len(c) == N
        assert sum(1 for x in c if x != 0) == tau

    @pytest.mark.parametrize("tau", [39, 49, 60])
    def test_coefficient_values(self, tau):
        """Non-zero coefficients must be +1 or -1."""
        ctilde = os.urandom(32)
        c = sample_in_ball(ctilde, tau)
        for x in c:
            assert x in (-1, 0, 1)

    def test_deterministic(self):
        ctilde = b'\x42' * 32
        assert sample_in_ball(ctilde, 39) == sample_in_ball(ctilde, 39)
