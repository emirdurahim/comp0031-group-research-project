"""Tests for FIPS 204 (ML-DSA) math primitives layer."""

from __future__ import annotations

import pytest

from src.algorithms.fips204.math import (
    Q, N, D, ZETA,
    mod_pos, reduce32,
    ntt, intt,
    poly_add, poly_sub, poly_pointwise, poly_multiply,
    power2round, decompose, high_bits, low_bits,
    make_hint, use_hint,
)


# ---------------------------------------------------------------------------
# Constants sanity checks
# ---------------------------------------------------------------------------

class TestConstants:
    def test_Q_is_prime(self):
        """Q = 8380417 = 2^23 - 2^13 + 1 should be prime."""
        from math import gcd
        # simple trial division up to sqrt(Q)
        for p in range(2, int(Q**0.5) + 1):
            assert Q % p != 0

    def test_Q_value(self):
        assert Q == 2**23 - 2**13 + 1

    def test_N_value(self):
        assert N == 256

    def test_D_value(self):
        assert D == 13

    def test_zeta_is_root_of_unity(self):
        """ZETA is a primitive 512th root of unity: ZETA^512 == 1, ZETA^256 == -1 mod Q."""
        assert pow(ZETA, 512, Q) == 1
        assert pow(ZETA, 256, Q) == Q - 1  # i.e. -1 mod Q


# ---------------------------------------------------------------------------
# Modular helpers
# ---------------------------------------------------------------------------

class TestModularHelpers:
    def test_mod_pos_range(self):
        for v in [-Q, -1, 0, 1, Q, Q + 1, 2 * Q]:
            assert 0 <= mod_pos(v) < Q

    def test_reduce32_near_zero(self):
        r = reduce32(0)
        assert -Q < r < Q


# ---------------------------------------------------------------------------
# NTT / INTT
# ---------------------------------------------------------------------------

class TestNTT:
    def test_roundtrip(self):
        """INTT(NTT(f)) == f for a random-looking polynomial."""
        f = [i % Q for i in range(N)]
        result = intt(ntt(f))
        for i in range(N):
            assert result[i] == f[i] % Q

    def test_zero_poly(self):
        f = [0] * N
        assert intt(ntt(f)) == f

    def test_ntt_does_not_mutate_input(self):
        f = [i for i in range(N)]
        original = list(f)
        ntt(f)
        assert f == original

    def test_intt_does_not_mutate_input(self):
        f_hat = ntt([i % Q for i in range(N)])
        original = list(f_hat)
        intt(f_hat)
        assert f_hat == original


# ---------------------------------------------------------------------------
# Polynomial arithmetic
# ---------------------------------------------------------------------------

class TestPolyArithmetic:
    def test_add_sub_inverse(self):
        f = [i % Q for i in range(N)]
        g = [(2 * i + 7) % Q for i in range(N)]
        h = poly_add(f, g)
        result = poly_sub(h, g)
        for i in range(N):
            assert result[i] == f[i] % Q

    def test_multiply_by_zero(self):
        f = [i % Q for i in range(N)]
        zero = [0] * N
        result = poly_multiply(f, zero)
        assert result == zero

    def test_multiply_by_one(self):
        """Multiplying by the 'constant 1' polynomial."""
        one = [1] + [0] * (N - 1)
        f = [(i * 17 + 3) % Q for i in range(N)]
        result = poly_multiply(f, one)
        for i in range(N):
            assert result[i] == f[i] % Q

    def test_pointwise_commutativity(self):
        f = [i % Q for i in range(N)]
        g = [(N - i) % Q for i in range(N)]
        assert poly_pointwise(f, g) == poly_pointwise(g, f)


# ---------------------------------------------------------------------------
# power2round
# ---------------------------------------------------------------------------

class TestPower2Round:
    @pytest.mark.parametrize("r", [0, 1, Q - 1, Q // 2, 1234567])
    def test_reconstruction(self, r):
        """r == r1 * 2^D + r0 (mod Q)."""
        r1, r0 = power2round(r)
        assert (r1 * (1 << D) + r0) % Q == r % Q

    def test_r0_range(self):
        """r0 must be in (-(2^(D-1)), 2^(D-1)]."""
        half = 1 << (D - 1)
        for r in range(0, Q, Q // 1000):
            _, r0 = power2round(r)
            assert -half < r0 <= half


# ---------------------------------------------------------------------------
# decompose / high_bits / low_bits
# ---------------------------------------------------------------------------

class TestDecompose:
    @pytest.mark.parametrize("alpha", [2 * 95_232, 2 * 261_888])
    def test_reconstruction(self, alpha):
        """r == r1 * alpha + r0 (mod Q) (when r != Q-1)."""
        for r in range(0, Q, Q // 500):
            r1, r0 = decompose(r, alpha)
            if r % Q == Q - 1:
                # special case
                continue
            assert (r1 * alpha + r0) % Q == r % Q

    @pytest.mark.parametrize("alpha", [2 * 95_232, 2 * 261_888])
    def test_high_low_match_decompose(self, alpha):
        for r in range(0, Q, Q // 200):
            r1, r0 = decompose(r, alpha)
            assert high_bits(r, alpha) == r1
            assert low_bits(r, alpha) == r0


# ---------------------------------------------------------------------------
# Hint operations
# ---------------------------------------------------------------------------

class TestHints:
    def test_make_hint_zero_when_no_change(self):
        alpha = 2 * 95_232
        r = 100
        h = make_hint(0, r, alpha)
        assert h == 0

    def test_use_hint_identity_when_h0(self):
        alpha = 2 * 95_232
        r = 12345
        r1 = high_bits(r, alpha)
        assert use_hint(0, r, alpha) == r1

    @pytest.mark.parametrize("alpha", [2 * 95_232, 2 * 261_888])
    def test_make_hint_returns_0_or_1(self, alpha):
        """make_hint always returns 0 or 1."""
        import random
        rng = random.Random(42)
        for _ in range(200):
            r = rng.randrange(Q)
            z = rng.randrange(Q)
            h = make_hint(z, r, alpha)
            assert h in (0, 1)

    @pytest.mark.parametrize("alpha", [2 * 95_232, 2 * 261_888])
    def test_use_hint_h0_returns_r1(self, alpha):
        """When h=0, use_hint returns high_bits(r)."""
        import random
        rng = random.Random(42)
        for _ in range(200):
            r = rng.randrange(Q)
            assert use_hint(0, r, alpha) == high_bits(r, alpha)
