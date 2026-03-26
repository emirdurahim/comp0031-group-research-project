import pytest
import os
from src.algorithms.fips205.parameters import get_params
from src.algorithms.fips205.address import ADRS
from src.algorithms.fips205.wots import base_2b, chain, wots_pkGen, wots_sign, wots_pkFromSig

def test_base_2b():
    # Example: b = 4, out_len = 4 => 2 bytes input
    X = bytes([0x12, 0x34])
    res = base_2b(X, 4, 4)
    # Expected: 1, 2, 3, 4
    assert res == [1, 2, 3, 4]

    # Test padding
    res = base_2b(X, 4, 6)
    assert res == [1, 2, 3, 4, 0, 0]

def test_wots_sign_verify_cycle():
    params = get_params("SLH-DSA-SHAKE-128s")
    n = params.n
    
    sk_seed = os.urandom(n)
    pk_seed = os.urandom(n)
    adrs = ADRS()
    
    msg = os.urandom(n)
    
    # Generate PK
    pk = wots_pkGen(sk_seed, pk_seed, adrs, params)
    assert len(pk) == n
    
    # Sign message
    sig = wots_sign(msg, sk_seed, pk_seed, adrs, params)
    assert len(sig) == params.length * n
    
    # Recover PK from signature
    recovered_pk = wots_pkFromSig(sig, msg, pk_seed, adrs, params)
    
    # The recovered PK should match the generated PK
    assert recovered_pk == pk
