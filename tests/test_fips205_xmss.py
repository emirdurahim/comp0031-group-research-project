import pytest
import os
from src.algorithms.fips205.parameters import get_params
from src.algorithms.fips205.address import ADRS
from src.algorithms.fips205.xmss import (
    xmss_node,
    xmss_sign,
    xmss_pkFromSig,
    ht_sign,
    ht_verify
)

def test_xmss_sign_verify_cycle():
    # Use 128f or 256f for faster testing
    params = get_params("SLH-DSA-SHAKE-128f")
    n = params.n
    
    sk_seed = os.urandom(n)
    pk_seed = os.urandom(n)
    adrs = ADRS()

    M = os.urandom(n)
    idx = 5  # arbitrary leaf index within the tree

    # 1. Sign
    sig_xmss = xmss_sign(M, sk_seed, idx, pk_seed, adrs.copy(), params)
    expected_xmss_len = (params.length + params.hp) * n
    assert len(sig_xmss) == expected_xmss_len

    # 2. Reconstruct root from signature
    recovered_root = xmss_pkFromSig(idx, sig_xmss, M, pk_seed, adrs.copy(), params)

    # 3. Calculate expected root manually
    expected_root = xmss_node(sk_seed, pk_seed, adrs.copy(), 0, params.hp, params)

    assert recovered_root == expected_root


def test_ht_sign_verify_cycle():
    params = get_params("SLH-DSA-SHAKE-128f")
    n = params.n
    
    sk_seed = os.urandom(n)
    pk_seed = os.urandom(n)
    idx_tree = 12345
    idx_leaf = 12

    M = b"test message"
    
    # 1. We need the original pk_root to verify against.
    # It is derived at the top layer: d - 1, and idx_tree depends on parsing structure
    adrs = ADRS()
    adrs.set_layer_address(params.d - 1)
    
    # Actually, SLH-DSA uses a single uniform root generation strategy during keygen.
    # Since d=22 for 128f, creating the true pk_root is fast enough for testing a single chain if we derive correctly.
    # However we can just run the same extraction process on ht_sign logic since we're just checking the HT component.
    
    pk_root = xmss_node(sk_seed, pk_seed, adrs, 0, params.hp, params)

    # Note: to do a full integration of pk_root, we really should sign a full chain
    # Instead, we just sign and use the highest level recovered root dynamically:
    
    sig_ht = ht_sign(M, sk_seed, pk_seed, idx_tree, idx_leaf, params)
    
    expected_ht_len = params.d * (params.length + params.hp) * n
    assert len(sig_ht) == expected_ht_len

    # For verification, we extract the root derived from signature to simulate the internal process smoothly:
    # Here's a trick to get the dynamic top root for testing the verify round-trip
    # without going through all keygen algorithms yet:
    xmss_sig_len = (params.length + params.hp) * params.n
    last_sig = sig_ht[(params.d - 1) * xmss_sig_len :]
    top_tree_idx = idx_tree >> (params.hp * (params.d - 1))
    top_leaf_idx = (idx_tree >> (params.hp * (params.d - 2))) % (1 << params.hp) if params.d > 1 else idx_leaf
    
    # Let's just trust `ht_verify` returns a boolean against the derived pk_root
    
    # Wait, the true root derived during keygen of top tree:
    adrs_top = ADRS()
    adrs_top.set_layer_address(params.d - 1)
    # The top layer has only 1 tree (index 0) per the standard construction.
    adrs_top.set_tree_address(0) 
    
    correct_pk_root = xmss_node(sk_seed, pk_seed, adrs_top, 0, params.hp, params)

    # 4. Verify
    is_valid = ht_verify(M, sig_ht, pk_seed, idx_tree, idx_leaf, correct_pk_root, params)
    assert is_valid is True

    # Check wrong message fails
    is_valid_wrong = ht_verify(b"wrong", sig_ht, pk_seed, idx_tree, idx_leaf, correct_pk_root, params)
    assert is_valid_wrong is False
