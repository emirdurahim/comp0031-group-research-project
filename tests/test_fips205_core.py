import pytest
import os
from src.algorithms.fips205.parameters import get_params
from src.algorithms.fips205.core import slh_keygen_internal, slh_sign_internal, slh_verify_internal

def test_slh_dsa_internal_cycle():
    # Keep using small variants to avoid slow evaluations during unit tests. 128f is fast.
    params = get_params("SLH-DSA-SHAKE-128f")
    n = params.n
    
    sk_seed = os.urandom(n)
    sk_prf = os.urandom(n)
    pk_seed = os.urandom(n)
    
    # Keygen
    sk, pk = slh_keygen_internal(sk_seed, sk_prf, pk_seed, params)
    
    assert len(sk) == params.sk_bytes
    assert len(pk) == params.pk_bytes
    
    M = b"Hello FIPS 205!"
    
    # Sign (using generated SK)
    sig = slh_sign_internal(M, sk, params)
    
    assert len(sig) == params.sig_bytes
    
    # Verify (using generated PK)
    is_valid = slh_verify_internal(M, sig, pk, params)
    assert is_valid is True
    
    # Tamper with message
    is_valid_wrong_m = slh_verify_internal(b"Hello fips 205!", sig, pk, params)
    assert is_valid_wrong_m is False

    # Tamper with signature
    tampered_sig = bytearray(sig)
    tampered_sig[0] ^= 1
    is_valid_wrong_sig = slh_verify_internal(M, bytes(tampered_sig), pk, params)
    assert is_valid_wrong_sig is False
