from typing import List, Annotated
import random
from Crypto.Hash import SHAKE128, SHA3_512, SHAKE256, SHA3_256
import os
from typing import Dict
from .base import EncapsulationResult, KEMAlgorithm, KeyPair

_PARAM_SETS: Dict[str, Dict[str, int]] = {
    "ML-KEM-512": {
        "k": 2,
        "q": 3329,
        "eta_1": 3,
        "eta_2": 2,
        "du": 10,
        "dv": 4,
        "shared_secret_bytes": 32,
        "public_key_bytes": 800,
        "secret_key_bytes": 1632,
        "ciphertext_bytes": 768,
    },
    "ML-KEM-768": {
        "k": 3,
        "q": 3329,
        "eta_1": 2,
        "eta_2": 2,
        "du": 10,
        "dv": 4,
        "shared_secret_bytes": 32,
        "public_key_bytes": 1184,
        "secret_key_bytes": 2400,
        "ciphertext_bytes": 1088,
    },
    "ML-KEM-1024": {
        "k": 4,
        "q": 3329,
        "eta_1": 2,
        "eta_2": 2,
        "du": 11,
        "dv": 5,
        "shared_secret_bytes": 32,
        "public_key_bytes": 1568,
        "secret_key_bytes": 3168,
        "ciphertext_bytes": 1568,
    },
}

PARAMETER_SETS: List[str] = list(_PARAM_SETS.keys())


class ML_KEM(KEMAlgorithm):
    def __init__(self, parameter_set: str = "HQC-128"):
        if parameter_set not in _PARAM_SETS:
            raise ValueError(
                f"Unknown FIPS-203 parameter set {parameter_set!r}. "
                f"Choose from {list(_PARAM_SETS)}"
            )
        self._parameter_set = parameter_set
        self._params = _PARAM_SETS[parameter_set]
        self._k = self._params["k"]
        self._q = self._params["q"]
        self._eta1 = self._params["eta_1"]
        self._eta2 = self._params["eta_2"]
        self._du = self._params["du"]
        self._dv = self._params["dv"]
        self._zeta = [
            1,
            1729,
            2580,
            3289,
            2642,
            630,
            1897,
            848,
            1062,
            1919,
            193,
            797,
            2786,
            3260,
            569,
            1746,
            296,
            2447,
            1339,
            1476,
            3046,
            56,
            2240,
            1333,
            1426,
            2094,
            535,
            2882,
            2393,
            2879,
            1974,
            821,
            289,
            331,
            3253,
            1756,
            1197,
            2304,
            2277,
            2055,
            650,
            1977,
            2513,
            632,
            2865,
            33,
            1320,
            1915,
            2319,
            1435,
            807,
            452,
            1438,
            2868,
            1534,
            2402,
            2647,
            2617,
            1481,
            648,
            2474,
            3110,
            1227,
            910,
            17,
            2761,
            583,
            2649,
            1637,
            723,
            2288,
            1100,
            1409,
            2662,
            3281,
            233,
            756,
            2156,
            3015,
            3050,
            1703,
            1651,
            2789,
            1789,
            1847,
            952,
            1461,
            2687,
            939,
            2308,
            2437,
            2388,
            733,
            2337,
            268,
            641,
            1584,
            2298,
            2037,
            3220,
            375,
            2549,
            2090,
            1645,
            1063,
            319,
            2773,
            757,
            2099,
            561,
            2466,
            2594,
            2804,
            1092,
            403,
            1026,
            1143,
            2150,
            2775,
            886,
            1722,
            1212,
            1874,
            1029,
            2110,
            2935,
            885,
            2154,
        ]
        self._zeta_sq = [
            17,
            -17,
            2761,
            -2761,
            583,
            -583,
            2649,
            -2649,
            1637,
            -1637,
            723,
            -723,
            2288,
            -2288,
            1100,
            -1100,
            1409,
            -1409,
            2662,
            -2662,
            3281,
            -3281,
            233,
            -233,
            756,
            -756,
            2156,
            -2156,
            3015,
            -3015,
            3050,
            -3050,
            1703,
            -1703,
            1651,
            -1651,
            2789,
            -2789,
            1789,
            -1789,
            1847,
            -1847,
            952,
            -952,
            1461,
            -1461,
            2687,
            -2687,
            939,
            -939,
            2308,
            -2308,
            2437,
            -2437,
            2388,
            -2388,
            733,
            -733,
            2337,
            -2337,
            268,
            -268,
            641,
            -641,
            1584,
            -1584,
            2298,
            -2298,
            2037,
            -2037,
            3220,
            -3220,
            375,
            -375,
            2549,
            -2549,
            2090,
            -2090,
            1645,
            -1645,
            1063,
            -1063,
            319,
            -319,
            2773,
            -2773,
            757,
            -757,
            2099,
            -2099,
            561,
            -561,
            2466,
            -2466,
            2594,
            -2594,
            2804,
            -2804,
            1092,
            -1092,
            403,
            -403,
            1026,
            -1026,
            1143,
            -1143,
            2150,
            -2150,
            2775,
            -2775,
            886,
            -886,
            1722,
            -1722,
            1212,
            -1212,
            1874,
            -1874,
            1029,
            -1029,
            2110,
            -2110,
            2935,
            -2935,
            885,
            -885,
            2154,
            -2154,
        ]

    @property
    def name(self) -> str:
        return "FIPS-203"

    @property
    def parameter_set(self) -> str:
        return self._parameter_set

    # Precompute frequently used constants
    _q_inv = pow(128, -1, 3329)

    # Algorithm 3
    def _bits_to_bytes(self, b: List[int]) -> List[int]:
        B = [0] * (len(b) // 8)
        for i in range(len(b)):
            B[i // 8] |= b[i] << (i % 8)
        return B

    # Algorithm 4
    def _bytes_to_bits(self, B: List[int]) -> List[int]:
        b = [0] * (8 * len(B))
        for i, val in enumerate(B):
            for j in range(8):
                b[8 * i + j] = (val >> j) & 1
        return b

    def _compress(self, x: int, d: int) -> int:
        return round((1 << d) / self._q * x) % (1 << d)

    def _decompress(self, y: int, d: int) -> int:
        return round((self._q / (1 << d)) * y)

    # Algorithm 5
    def _byte_encode(self, F: List[int], d: int) -> List[int]:
        b = [0] * (len(F) * d)
        for i, a in enumerate(F):
            for j in range(d):
                b[i * d + j] = a & 1
                a >>= 1
        return self._bits_to_bytes(b)

    # Algorithm 6
    def _byte_decode(self, B: List[int], d: int) -> List[int]:
        b = self._bytes_to_bits(B)
        F = [0] * 256
        for i in range(256):
            val = 0
            for j in range(d):
                val |= b[i * d + j] << j
            F[i] = val
        return F

    # Algorithm 7
    def _sample_ntt(self, B: List[int]) -> List[int]:
        ctx = SHAKE128.new(bytes(B))
        j = 0
        a = [0] * 256
        while j < 256:
            C = ctx.read(3)
            d1 = C[0] | ((C[1] & 0x0F) << 8)
            d2 = (C[1] >> 4) | (C[2] << 4)
            if d1 < self._q:
                a[j] = d1
                j += 1
            if d2 < self._q and j < 256:
                a[j] = d2
                j += 1
        return a

    # Algorithm 8
    def _sample_poly_cbd(self, B: List[int], eta: int):
        b = self._bytes_to_bits(B)
        f = [0] * 256
        for i in range(256):
            x = sum(b[2 * i * eta : 2 * i * eta + eta])
            y = sum(b[(2 * i + 1) * eta : (2 * i + 1) * eta + eta])
            f[i] = (x - y) % self._q
        return f

    def _ntt(self, f: List[int]) -> List[int]:
        f_hat = list(f)
        i = 1
        le = 128
        q = self._q
        zeta_list = self._zeta
        while le >= 2:
            for start in range(0, 256, 2 * le):
                zeta = zeta_list[i]
                i += 1
                for j in range(start, start + le):
                    j_le = j + le
                    t = (zeta * f_hat[j_le]) % q
                    f_hat[j_le] = (f_hat[j] - t) % q
                    f_hat[j] = (f_hat[j] + t) % q
            le //= 2
        return f_hat

    # Algorithm 10
    def _ntt_inverse(self, f_hat: List[int]) -> List[int]:
        f = list(f_hat)
        i = 127
        le = 2
        q = self._q
        zeta_list = self._zeta
        while le <= 128:
            for start in range(0, 256, 2 * le):
                zeta = zeta_list[i]
                i -= 1
                for j in range(start, start + le):
                    j_le = j + le
                    t = f[j]
                    f[j] = (t + f[j_le]) % q
                    f[j_le] = (zeta * (f[j_le] - t)) % q
            le *= 2

        q_inv = self._q_inv
        for i in range(256):
            f[i] = (f[i] * q_inv) % q
        return f

    def _multiply_ntts(self, f_hat: List[int], g_hat: List[int]) -> List[int]:
        h_hat = [0] * 256
        q = self._q
        z_sq = self._zeta_sq
        for i in range(128):
            idx = 2 * i
            a0, a1 = f_hat[idx], f_hat[idx + 1]
            b0, b1 = g_hat[idx], g_hat[idx + 1]
            gamma = z_sq[i]

            h_hat[idx] = (a0 * b0 + a1 * b1 * gamma) % q
            h_hat[idx + 1] = (a0 * b1 + a1 * b0) % q
        return h_hat

    def _G(self, d: List[int]) -> tuple[List[int], List[int]]:
        sha = SHA3_512.new()
        sha = sha.update(bytes(d))
        hash = sha.digest()
        return (list(hash[:32]), list(hash[32:]))

    def _H(self, s: list[int]) -> Annotated[list[int], 32]:
        sha = SHA3_256.new()
        sha = sha.update(bytes(s))
        hash = sha.digest()
        return list(hash)

    def _J(self, s: list[int]) -> Annotated[list[int], 32]:
        shake = SHAKE256.new()
        shake = shake.update(bytes(s))
        return list(shake.read(8 * 32))

    def _prf(self, s: List[int], b: int, eta: int) -> List[int]:
        shake = SHAKE256.new()
        shake = shake.update(bytes(s + [b]))
        return list(shake.read(8 * 64 * eta))

    def _matrix_vector_multiply(
        self, A: List[List[int]], u: List[int], i: int
    ) -> List[int]:
        w_i = [0] * 256
        for j in range(self._k):
            poly_A = A[i][j]
            poly_u = u[j]

            for coeff in range(128):
                idx = 2 * coeff
                a0, a1 = poly_A[idx], poly_A[idx + 1]
                b0, b1 = poly_u[idx], poly_u[idx + 1]
                gamma = self._zeta_sq[coeff]

                c0 = (a0 * b0 + a1 * b1 * gamma) % self._q
                c1 = (a0 * b1 + a1 * b0) % self._q

                w_i[idx] = (w_i[idx] + c0) % self._q
                w_i[idx + 1] = (w_i[idx + 1] + c1) % self._q
        return w_i

    # Algorithm 13
    def _k_pke_key_gen(self, d: List[int]) -> tuple[List[int], List[int]]:
        A_hat = [[0 for _ in range(self._k)] for _ in range(self._k)]
        rho, sigma = self._G(d + [self._k])
        s = [0] * self._k
        e = [0] * self._k
        N = 0
        for i in range(self._k):
            for j in range(self._k):
                A_hat[i][j] = self._sample_ntt(rho + [j, i])
        for i in range(self._k):
            s[i] = self._sample_poly_cbd(self._prf(sigma, N, self._eta1), self._eta1)
            N += 1
        for i in range(self._k):
            e[i] = self._sample_poly_cbd(self._prf(sigma, N, self._eta1), self._eta1)
            N += 1
        s_hat = [self._ntt(poly) for poly in s]
        e_hat = [self._ntt(poly) for poly in e]

        t_hat = []
        for i in range(self._k):
            res_poly = list(e_hat[i])
            for j in range(self._k):
                poly_A = A_hat[i][j]
                poly_s = s_hat[j]
                for coeff in range(128):
                    idx = 2 * coeff
                    a0, a1 = poly_A[idx], poly_A[idx + 1]
                    b0, b1 = poly_s[idx], poly_s[idx + 1]
                    gamma = self._zeta_sq[coeff]

                    c0 = (a0 * b0 + a1 * b1 * gamma) % self._q
                    c1 = (a0 * b1 + a1 * b0) % self._q

                    res_poly[idx] = (res_poly[idx] + c0) % self._q
                    res_poly[idx + 1] = (res_poly[idx + 1] + c1) % self._q
            t_hat.append(res_poly)

        ek_pke = []
        for poly in t_hat:
            ek_pke.extend(self._byte_encode(poly, 12))
        ek_pke += rho

        dk_pke = []
        for poly in s_hat:
            dk_pke.extend(self._byte_encode(poly, 12))

        return (ek_pke, dk_pke)

    def _k_pke_encrypt(
        self, ek_pke: list[int], m: list[int], r: list[int]
    ) -> list[int]:
        N = 0
        t_hat_bytes = ek_pke[0 : 384 * self._k]
        rho = ek_pke[384 * self._k : 384 * self._k + 32]

        # Decode t_hat polynomials
        t_hat = []
        for i in range(self._k):
            t_hat.append(self._byte_decode(t_hat_bytes[384 * i : 384 * (i + 1)], 12))

        A_hat = [[0 for _ in range(self._k)] for _ in range(self._k)]
        for i in range(self._k):
            for j in range(self._k):
                # We sample exactly as KeyGen did
                A_hat[i][j] = self._sample_ntt(rho + [j, i])

        y = []
        for i in range(self._k):
            y.append(self._sample_poly_cbd(self._prf(r, N, self._eta1), self._eta1))
            N += 1

        e1 = []
        for i in range(self._k):
            e1.append(self._sample_poly_cbd(self._prf(r, N, self._eta2), self._eta2))
            N += 1

        e2 = self._sample_poly_cbd(self._prf(r, N, self._eta2), self._eta2)
        y_hat = [self._ntt(poly) for poly in y]

        # Compute u: u = A^T ∘ y + e1
        u = []
        for i in range(self._k):
            tmp_poly_hat = [0] * 256
            for j in range(self._k):
                # Transpose: A_hat[j][i]
                poly_A = A_hat[j][i]
                poly_y = y_hat[j]
                for coeff in range(128):
                    idx = 2 * coeff
                    a0, a1 = poly_A[idx], poly_A[idx + 1]
                    b0, b1 = poly_y[idx], poly_y[idx + 1]
                    gamma = self._zeta_sq[coeff]

                    c0 = (a0 * b0 + a1 * b1 * gamma) % self._q
                    c1 = (a0 * b1 + a1 * b0) % self._q

                    tmp_poly_hat[idx] = (tmp_poly_hat[idx] + c0) % self._q
                    tmp_poly_hat[idx + 1] = (tmp_poly_hat[idx + 1] + c1) % self._q

            poly_u = self._ntt_inverse(tmp_poly_hat)
            e1_i = e1[i]
            u.append([(poly_u[n] + e1_i[n]) % self._q for n in range(256)])

        # Message encoding
        m_bits = self._bytes_to_bits(m)
        q_half = self._q // 2
        m_poly = [bit * q_half for bit in m_bits]

        # Compute v: v = t^T ∘ y + e2 + m
        v_hat = [0] * 256
        for j in range(self._k):
            poly_t = t_hat[j]
            poly_y = y_hat[j]
            for coeff in range(128):
                idx = 2 * coeff
                a0, a1 = poly_t[idx], poly_t[idx + 1]
                b0, b1 = poly_y[idx], poly_y[idx + 1]
                gamma = self._zeta_sq[coeff]

                c0 = (a0 * b0 + a1 * b1 * gamma) % self._q
                c1 = (a0 * b1 + a1 * b0) % self._q

                v_hat[idx] = (v_hat[idx] + c0) % self._q
                v_hat[idx + 1] = (v_hat[idx + 1] + c1) % self._q

        v_base = self._ntt_inverse(v_hat)
        v = [(v_base[n] + e2[n] + m_poly[n]) % self._q for n in range(256)]

        # Encode ciphertexts
        c1 = []
        for poly in u:
            compressed = [self._compress(x, self._du) for x in poly]
            c1.extend(self._byte_encode(compressed, self._du))

        compressed_v = [self._compress(x, self._dv) for x in v]
        c2 = self._byte_encode(compressed_v, self._dv)

        return c1 + c2

    def _k_pke_decrypt(self, dk_pke: list[int], c: list[int]) -> list[int]:
        du_k_32 = 32 * self._du * self._k
        c1 = c[0:du_k_32]
        c2 = c[du_k_32 : 32 * (self._du * self._k + self._dv)]

        u = []
        step = 32 * self._du
        for i in range(self._k):
            poly_bytes = c1[i * step : (i + 1) * step]
            u.append(
                [
                    self._decompress(x, self._du)
                    for x in self._byte_decode(poly_bytes, self._du)
                ]
            )

        v_coeffs = self._byte_decode(c2, self._dv)
        v = [self._decompress(x, self._dv) for x in v_coeffs]

        s_hat = []
        for i in range(self._k):
            poly_bytes = dk_pke[i * 384 : (i + 1) * 384]
            s_hat.append(self._byte_decode(poly_bytes, 12))

        u_hat = [self._ntt(poly) for poly in u]

        s_dot_u_hat = [0] * 256
        for i in range(self._k):
            poly_s = s_hat[i]
            poly_u = u_hat[i]
            for coeff in range(128):
                idx = 2 * coeff
                a0, a1 = poly_s[idx], poly_s[idx + 1]
                b0, b1 = poly_u[idx], poly_u[idx + 1]
                gamma = self._zeta_sq[coeff]

                c0 = (a0 * b0 + a1 * b1 * gamma) % self._q
                c1 = (a0 * b1 + a1 * b0) % self._q

                s_dot_u_hat[idx] = (s_dot_u_hat[idx] + c0) % self._q
                s_dot_u_hat[idx + 1] = (s_dot_u_hat[idx + 1] + c1) % self._q

        mask = self._ntt_inverse(s_dot_u_hat)
        w = [(v[n] - mask[n]) % 3329 for n in range(256)]
        m_bits = [self._compress(x, 1) for x in w]
        return self._byte_encode(m_bits, 1)

    # Algorithm 16
    def _key_gen_internal(
        self, d: Annotated[list[int], 32], z: Annotated[list[int], 32]
    ) -> tuple[list[int], list[int]]:
        ek_pke, dk_pke = self._k_pke_key_gen(d)
        ek = ek_pke
        dk = dk_pke + ek + self._H(ek) + z
        return ek, dk

    # Algorithm 17
    def _encaps_internal(
        self, ek: list[int], m: Annotated[list[int], 32]
    ) -> tuple[Annotated[list[int], 32], list[int]]:
        K, r = self._G(m + self._H(ek))
        c = self._k_pke_encrypt(ek, m, r)
        return K, c

    # Algorithm 18
    def _decaps_internal(self, dk: list[int], c: list[int]) -> Annotated[list[int], 32]:
        dk_pke = dk[0 : 384 * self._k]
        ek_pke = dk[384 * self._k : 768 * self._k + 32]
        h = dk[768 * self._k + 32 : 768 * self._k + 64]
        z = dk[768 * self._k + 64 : 768 * self._k + 96]
        m = self._k_pke_decrypt(dk_pke, c)
        (K, r) = self._G(m + h)
        K_bar = self._J(z + c)
        c_prime = self._k_pke_encrypt(ek_pke, m, r)
        if c != c_prime:
            K = K_bar
        return K

    # Algorithm 19
    def keygen(self) -> KeyPair:
        d = os.urandom(32)
        z = os.urandom(32)
        ek, dk = self._key_gen_internal(list(d), list(z))
        return KeyPair(public_key=ek, secret_key=dk)

    # Algorithm 20
    def encapsulate(self, ek: list[int]) -> EncapsulationResult:
        poly_len = 384
        t_hat_bytes = ek[0 : poly_len * self._k]

        re_encoded_t_hat = []
        for i in range(self._k):
            poly_segment = t_hat_bytes[i * poly_len : (i + 1) * poly_len]
            decoded = self._byte_decode(poly_segment, 12)
            re_encoded_t_hat.extend(self._byte_encode(decoded, 12))

        if len(ek) != poly_len * self._k + 32 or re_encoded_t_hat != t_hat_bytes:
            raise ValueError("Invalid parameters")
        m = os.urandom(32)
        K, c = self._encaps_internal(ek, list(m))
        return EncapsulationResult(ciphertext=c, shared_secret=K)

    # Algorithm 21
    def decapsulate(self, c: list[int], dk: list[int]) -> bytes:
        if (
            len(c) != 32 * (self._du * self._k + self._dv)
            or len(dk) != 768 * self._k + 96
            or self._H(dk[384 * self._k : 768 * self._k + 32])
            != dk[768 * self._k + 32 : 768 * self._k + 64]
        ):
            raise ValueError("Invalid parameters")
        K = self._decaps_internal(dk, c)
        return bytes(K)


if __name__ == "__main__":
    kem = ML_KEM("ML-KEM-512")
    ek, dk = kem.key_gen()
    result = kem.encaps(ek)
    K_prime = kem.decaps(dk, result.ciphertext)
    print(len(K_prime))
    print(result.shared_secret == K_prime)
