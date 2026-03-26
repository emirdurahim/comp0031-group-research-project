import pytest
import hashlib
from src.algorithms.fips205.hash_functions import H_msg, PRF, PRF_msg, F, H, T_l
from src.algorithms.fips205.address import ADRS

def test_H_msg():
    R = b"R" * 16
    pk_seed = b"P" * 16
    pk_root = b"K" * 16
    m = b"message"
    out_len = 30  # e.g., m=30 for 128s
    
    expected = hashlib.shake_256(R + pk_seed + pk_root + m).digest(out_len)
    result = H_msg(R, pk_seed, pk_root, m, out_len)
    assert result == expected

def test_PRF():
    pk_seed = b"P" * 16
    sk_seed = b"S" * 16
    adrs = ADRS(b"A" * 32)
    n = 16
    
    expected = hashlib.shake_256(pk_seed + adrs.to_bytes() + sk_seed).digest(n)
    result = PRF(pk_seed, sk_seed, adrs, n)
    assert result == expected

def test_PRF_msg():
    sk_prf = b"S" * 16
    opt_rand = b"O" * 16
    m = b"message"
    n = 16
    
    expected = hashlib.shake_256(sk_prf + opt_rand + m).digest(n)
    result = PRF_msg(sk_prf, opt_rand, m, n)
    assert result == expected

def test_F():
    pk_seed = b"P" * 16
    adrs = ADRS(b"A" * 32)
    m1 = b"shortmsg"
    n = 16
    
    expected = hashlib.shake_256(pk_seed + adrs.to_bytes() + m1).digest(n)
    result = F(pk_seed, adrs, m1, n)
    assert result == expected

def test_H():
    pk_seed = b"P" * 16
    adrs = ADRS(b"A" * 32)
    m2 = b"nodepair" * 2
    n = 16
    
    expected = hashlib.shake_256(pk_seed + adrs.to_bytes() + m2).digest(n)
    result = H(pk_seed, adrs, m2, n)
    assert result == expected

def test_T_l():
    pk_seed = b"P" * 16
    adrs = ADRS(b"A" * 32)
    ml = b"verylongmessage" * 4
    n = 16
    
    expected = hashlib.shake_256(pk_seed + adrs.to_bytes() + ml).digest(n)
    result = T_l(pk_seed, adrs, ml, n)
    assert result == expected
