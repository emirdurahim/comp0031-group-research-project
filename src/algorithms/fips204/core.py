"""CRYSTALS-Dilithium (FIPS 204) - Core keygen / sign / verify.

Implements FIPS 204 Algorithms 1 (ML-DSA.KeyGen), 2 (ML-DSA.Sign),
and 3 (ML-DSA.Verify) using Layers 1-3.
"""

from __future__ import annotations

import hashlib
import os
from typing import Dict, List, Tuple

from .math import (
    Q, N, D, Poly,
    ntt, intt, mod_pos,
    poly_add, poly_sub, poly_pointwise,
    power2round, high_bits, low_bits,
    make_hint, use_hint,
)
from .sampling import (
    _shake256,
    expand_a, expand_s, expand_mask, sample_in_ball,
)
from .encoding import (
    pk_encode, pk_decode,
    sk_encode, sk_decode,
    sig_encode, sig_decode,
    w1_encode,
)

# ---------------------------------------------------------------------------
# Parameter sets  (FIPS 204, Table 1)
# ---------------------------------------------------------------------------

_PARAMS: Dict[str, Dict] = {
    "ML-DSA-44": {
        "k": 4, "l": 4,
        "eta": 2, "tau": 39,
        "gamma1": 1 << 17, "gamma2": 95_232,
        "omega": 80,
        "ctilde_len": 32,
    },
    "ML-DSA-65": {
        "k": 6, "l": 5,
        "eta": 4, "tau": 49,
        "gamma1": 1 << 19, "gamma2": 261_888,
        "omega": 55,
        "ctilde_len": 48,
    },
    "ML-DSA-87": {
        "k": 8, "l": 7,
        "eta": 2, "tau": 60,
        "gamma1": 1 << 19, "gamma2": 261_888,
        "omega": 75,
        "ctilde_len": 64,
    },
}


# ---------------------------------------------------------------------------
# Vector / matrix helpers  (NTT domain)
# ---------------------------------------------------------------------------

def _ntt_vec(v: List[Poly]) -> List[Poly]:
    """Apply NTT to each polynomial in a vector."""
    return [ntt(p) for p in v]


def _intt_vec(v: List[Poly]) -> List[Poly]:
    """Apply INTT to each polynomial in a vector."""
    return [intt(p) for p in v]


def _mat_vec_ntt(A_hat: List[List[Poly]], v_hat: List[Poly]) -> List[Poly]:
    """Multiply matrix A_hat (NTT domain) by vector v_hat (NTT domain).

    Returns a vector of k polynomials, still in NTT domain.
    """
    k = len(A_hat)
    l = len(v_hat)
    result = []
    for i in range(k):
        acc = [0] * N
        for j in range(l):
            pw = poly_pointwise(A_hat[i][j], v_hat[j])
            acc = poly_add(acc, pw)
        result.append(acc)
    return result


def _vec_add(a: List[Poly], b: List[Poly]) -> List[Poly]:
    return [poly_add(a[i], b[i]) for i in range(len(a))]


def _vec_sub(a: List[Poly], b: List[Poly]) -> List[Poly]:
    return [poly_sub(a[i], b[i]) for i in range(len(a))]


def _scalar_vec_ntt(c_hat: Poly, v_hat: List[Poly]) -> List[Poly]:
    """Multiply scalar polynomial c_hat by each element of v_hat (NTT domain)."""
    return [poly_pointwise(c_hat, vi) for vi in v_hat]


# ---------------------------------------------------------------------------
# Infinity norm
# ---------------------------------------------------------------------------

def _poly_inf_norm(p: Poly) -> int:
    """Max absolute value of any coefficient (centred around Q/2)."""
    m = 0
    for c in p:
        c_mod = c % Q
        if c_mod > Q // 2:
            c_mod = Q - c_mod
        if c_mod > m:
            m = c_mod
    return m


def _vec_inf_norm(v: List[Poly]) -> int:
    return max(_poly_inf_norm(p) for p in v)


# ---------------------------------------------------------------------------
# Count hints
# ---------------------------------------------------------------------------

def _count_hints(h: List[List[int]]) -> int:
    return sum(len(hi) for hi in h)


# ===================================================================
# KeyGen  (FIPS 204 Algorithm 1)
# ===================================================================

def ml_dsa_keygen(param_set: str) -> Tuple[bytes, bytes]:
    """Generate a Dilithium key pair."""
    p = _PARAMS[param_set]
    k, l, eta = p["k"], p["l"], p["eta"]

    # Step 1: random seed
    xi = os.urandom(32)

    # Step 2: derive rho, rhoprime, K from seed
    expanded = _shake256(xi, 128)
    rho = expanded[:32]
    rhoprime = expanded[32:96]
    K = expanded[96:128]

    # Step 3: expand public matrix A_hat (in NTT domain)
    A_hat = expand_a(rho, k, l)

    # Step 4: sample secret vectors
    s1, s2 = expand_s(rhoprime, k, l, eta)

    # Step 5: NTT(s1)
    s1_hat = _ntt_vec(s1)

    # Step 6: t = A * s1 + s2  (compute in NTT domain, then INTT)
    As1_hat = _mat_vec_ntt(A_hat, s1_hat)
    As1 = _intt_vec(As1_hat)
    t = _vec_add(As1, s2)

    # Step 7: power2round(t) -> (t1, t0)
    t1 = []
    t0 = []
    for poly in t:
        t1_poly = []
        t0_poly = []
        for c in poly:
            r1, r0 = power2round(mod_pos(c))
            t1_poly.append(r1)
            t0_poly.append(r0)
        t1.append(t1_poly)
        t0.append(t0_poly)

    # Step 8: encode public key
    pk = pk_encode(rho, t1)

    # Step 9: tr = H(pk, 64)
    tr = _shake256(pk, 64)

    # Step 10: encode secret key
    sk = sk_encode(rho, K, tr, s1, s2, t0, eta)

    return pk, sk


# ===================================================================
# Sign  (FIPS 204 Algorithm 2)
# ===================================================================

def ml_dsa_sign(sk: bytes, message: bytes, param_set: str) -> bytes:
    """Sign a message using Dilithium."""
    p = _PARAMS[param_set]
    k, l, eta = p["k"], p["l"], p["eta"]
    gamma1, gamma2 = p["gamma1"], p["gamma2"]
    tau, omega = p["tau"], p["omega"]
    ctilde_len = p["ctilde_len"]
    beta = tau * eta

    # Step 1: decode secret key
    rho, K, tr, s1, s2, t0 = sk_decode(sk, k, l, eta)

    # Step 2: expand A_hat
    A_hat = expand_a(rho, k, l)

    # Step 3: NTT the secret vectors
    s1_hat = _ntt_vec(s1)
    s2_hat = _ntt_vec(s2)
    t0_hat = _ntt_vec(t0)

    # Step 4: mu = H(tr || message, 64)
    mu = _shake256(tr + message, 64)

    # Step 5: rhoprime = H(K || mu, 64)  (deterministic signing)
    rhoprime = _shake256(K + mu, 64)

    # Step 6: rejection sampling loop
    kappa = 0
    while True:
        # Step 7: y = ExpandMask(rhoprime, kappa)
        y = expand_mask(rhoprime, kappa, l, gamma1)

        # Step 8: w = A * NTT(y) in NTT domain, then INTT
        y_hat = _ntt_vec(y)
        w_hat = _mat_vec_ntt(A_hat, y_hat)
        w = _intt_vec(w_hat)

        # Step 9: w1 = HighBits(w)
        w1 = []
        for poly in w:
            w1.append([high_bits(mod_pos(c), 2 * gamma2) for c in poly])

        # Step 10: ctilde = H(mu || w1Encode(w1), ctilde_len)
        w1_bytes = w1_encode(w1, gamma2)
        ctilde = _shake256(mu + w1_bytes, ctilde_len)

        # Step 11: c = SampleInBall(ctilde)
        c_poly = sample_in_ball(ctilde, tau)
        c_hat = ntt(c_poly)

        # Step 12: z = y + c * s1  (NTT domain)
        cs1_hat = _scalar_vec_ntt(c_hat, s1_hat)
        cs1 = _intt_vec(cs1_hat)
        z = _vec_add(y, cs1)

        # Step 13: r0 = LowBits(w - c*s2)
        cs2_hat = _scalar_vec_ntt(c_hat, s2_hat)
        cs2 = _intt_vec(cs2_hat)
        r = _vec_sub(w, cs2)

        # Step 14: rejection check 1 - ||z||_inf >= gamma1 - beta
        if _vec_inf_norm(z) >= gamma1 - beta:
            kappa += l
            continue

        # Step 15: rejection check 2 - ||r0||_inf >= gamma2 - beta
        r0_vec = []
        for poly in r:
            r0_vec.append([low_bits(mod_pos(c), 2 * gamma2) for c in poly])
        if _vec_inf_norm(r0_vec) >= gamma2 - beta:
            kappa += l
            continue

        # Step 16: compute hints
        ct0_hat = _scalar_vec_ntt(c_hat, t0_hat)
        ct0 = _intt_vec(ct0_hat)

        # Check ||ct0||_inf < gamma2
        if _vec_inf_norm(ct0) >= gamma2:
            kappa += l
            continue

        w_minus_cs2_plus_ct0 = _vec_add(r, ct0)

        h: List[List[int]] = []
        for i in range(k):
            hints_i = []
            for j in range(N):
                hi = make_hint(
                    mod_pos(ct0[i][j]),
                    mod_pos(r[i][j]),
                    2 * gamma2,
                )
                if hi:
                    hints_i.append(j)
            h.append(hints_i)

        # Step 17: check hint count
        if _count_hints(h) > omega:
            kappa += l
            continue

        # Step 18: encode and return signature
        # Ensure z coefficients are in [-(gamma1-1), gamma1]
        z_centred = []
        for poly in z:
            z_centred.append([c - Q if c > Q // 2 else c for c in poly])

        return sig_encode(ctilde, z_centred, h, gamma1, omega, k)


# ===================================================================
# Verify  (FIPS 204 Algorithm 3)
# ===================================================================

def ml_dsa_verify(pk: bytes, message: bytes, signature: bytes,
                  param_set: str) -> bool:
    """Verify a Dilithium signature."""
    p = _PARAMS[param_set]
    k, l = p["k"], p["l"]
    gamma1, gamma2 = p["gamma1"], p["gamma2"]
    tau, eta, omega = p["tau"], p["eta"], p["omega"]
    ctilde_len = p["ctilde_len"]
    beta = tau * eta

    # Step 1: decode public key
    rho, t1 = pk_decode(pk, k)

    # Step 2: decode signature
    decoded = sig_decode(signature, l, k, gamma1, omega, ctilde_len)
    if decoded is None:
        return False
    ctilde, z, h = decoded

    # Step 3: check ||z||_inf < gamma1 - beta
    if _vec_inf_norm(z) >= gamma1 - beta:
        return False

    # Step 4: expand A_hat
    A_hat = expand_a(rho, k, l)

    # Step 5: tr = H(pk, 64)
    tr = _shake256(pk, 64)

    # Step 6: mu = H(tr || message, 64)
    mu = _shake256(tr + message, 64)

    # Step 7: c = SampleInBall(ctilde)
    c_poly = sample_in_ball(ctilde, tau)
    c_hat = ntt(c_poly)

    # Step 8: w' = A*NTT(z) - c*NTT(t1 * 2^d)   (all in NTT domain)
    z_hat = _ntt_vec(z)
    Az_hat = _mat_vec_ntt(A_hat, z_hat)

    # t1 * 2^d, then NTT
    t1_scaled = []
    for poly in t1:
        t1_scaled.append([c << D for c in poly])
    t1_scaled_hat = _ntt_vec(t1_scaled)

    ct1_hat = _scalar_vec_ntt(c_hat, t1_scaled_hat)

    # w'_approx = A*z - c*t1*2^d  (in NTT domain, then INTT)
    w_prime_hat = [poly_sub(Az_hat[i], ct1_hat[i]) for i in range(k)]
    w_prime = _intt_vec(w_prime_hat)

    # Step 9: w1' = UseHint(h, w')
    w1_prime = []
    for i in range(k):
        w1_poly = [0] * N
        hint_set = set(h[i])
        for j in range(N):
            hi = 1 if j in hint_set else 0
            w1_poly[j] = use_hint(hi, mod_pos(w_prime[i][j]), 2 * gamma2)
        w1_prime.append(w1_poly)

    # Step 10: ctilde' = H(mu || w1Encode(w1'), ctilde_len)
    w1_bytes = w1_encode(w1_prime, gamma2)
    ctilde_prime = _shake256(mu + w1_bytes, ctilde_len)

    # Step 11: check ctilde == ctilde'
    # Also check total hints <= omega
    if _count_hints(h) > omega:
        return False

    return ctilde == ctilde_prime
