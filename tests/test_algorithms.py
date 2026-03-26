import pytest

from src.algorithms.base import KEMAlgorithm, SignatureAlgorithm
from src.algorithms.fips203 import ML_KEM, PARAMETER_SETS as ML_KEM_PARAM_SETS
from src.algorithms.fips204 import ML_DSA, PARAMETER_SETS as DILITHIUM_PARAM_SETS
from src.algorithms.fips205 import SLH_DSA, PARAMETER_SETS as SLH_DSA_PARAM_SETS


def _check_kem_interface(kem: KEMAlgorithm) -> None:
    kp = kem.keygen()
    assert kp is not None
    assert kp.public_key is not None
    assert kp.secret_key is not None

    enc = kem.encapsulate(kp.public_key)
    assert enc is not None
    assert enc.ciphertext is not None
    assert enc.shared_secret is not None

    shared_secret = kem.decapsulate(kp.secret_key, enc.ciphertext)
    assert shared_secret == enc.shared_secret


def _check_signature_interface(alg: SignatureAlgorithm) -> None:
    kp = alg.keygen()
    assert kp is not None

    message = b"Test message for signature"
    signature = alg.sign(kp.secret_key, message)
    assert signature is not None
    assert isinstance(signature, bytes)

    assert alg.verify(kp.public_key, message, signature) is True
    assert alg.verify(kp.public_key, b"Wrong message", signature) is False

    bad_sig = bytearray(signature)
    bad_sig[0] ^= 1
    assert alg.verify(kp.public_key, message, bytes(bad_sig)) is False


class TestML_KEM:
    def test_default_parameter_set(self):
        alg = ML_KEM()
        assert alg.parameter_set == "ML-KEM-512"

    @pytest.mark.parametrize("param_set", ML_KEM_PARAM_SETS)
    def test_interface(self, param_set):
        alg = ML_KEM(param_set)
        _check_kem_interface(alg)


class TestDilithium:
    def test_default_parameter_set(self):
        alg = ML_DSA()
        assert alg.parameter_set == "ML-DSA-44"

    @pytest.mark.parametrize("param_set", DILITHIUM_PARAM_SETS)
    def test_interface(self, param_set):
        alg = ML_DSA(param_set)
        _check_signature_interface(alg)


class TestSLH_DSA:
    def test_default_parameter_set(self):
        alg = SLH_DSA()
        assert alg.parameter_set == "SLH-DSA-SHAKE-128s"

    @pytest.mark.parametrize("param_set", SLH_DSA_PARAM_SETS)
    def test_interface(self, param_set):
        alg = SLH_DSA(param_set)
        _check_signature_interface(alg)

    @pytest.mark.parametrize("param_set", SLH_DSA_PARAM_SETS)
    def test_key_sizes(self, param_set):
        alg = SLH_DSA(param_set)
        kp = alg.keygen()
        assert len(kp.public_key) == alg._params.pk_bytes
        assert len(kp.secret_key) == alg._params.sk_bytes

    @pytest.mark.slow
    @pytest.mark.parametrize("param_set", SLH_DSA_PARAM_SETS)
    def test_signature_size(self, param_set):
        alg = SLH_DSA(param_set)
        kp = alg.keygen()
        sig = alg.sign(kp.secret_key, b"short message")
        assert len(sig) == alg._params.sig_bytes

    def test_invalid_parameter_set(self):
        with pytest.raises(ValueError):
            SLH_DSA("Invalid-Set")

    def test_wrong_signature(self):
        alg = SLH_DSA("SLH-DSA-SHAKE-128f")
        kp = alg.keygen()
        msg = b"hello"
        sig = bytearray(alg.sign(kp.secret_key, msg))
        sig[0] ^= 1
        assert alg.verify(kp.public_key, msg, bytes(sig)) is False
