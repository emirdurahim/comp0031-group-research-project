import pytest
import os
from src.algorithms.fips205.parameters import get_params
from src.algorithms.fips205.address import ADRS
from src.algorithms.fips205.fors import fors_skGen, fors_node, fors_sign, fors_pkFromSig

def test_fors_sign_verify_cycle():
    # Use 128f or 256f for faster testing execution as per instruction suggestion
    params = get_params("SLH-DSA-SHAKE-128f")
    n = params.n
    
    sk_seed = os.urandom(n)
    pk_seed = os.urandom(n)
    adrs = ADRS()

    # The digest size for FORS is k*a bits, so we need ceil(k*a / 8) bytes.
    # We can just generate random bytes to simulate a message digest.
    md_len = (params.k * params.a + 7) // 8
    md = os.urandom(md_len)

    # Calculate actual expected public key based purely on root nodes
    # so we can compare it to the one recovered from the signature.
    # T_l(pk_seed, adrs, concat(all_roots), n)
    # The root of the i-th tree is at height `a` and index `i`.
    
    adrs_roots = adrs.copy()
    adrs_roots.set_type_and_clear(ADRS.FORS_ROOTS)
    expected_roots = bytearray()
    
    for i in range(params.k):
        # We manually compute the recursive tree root
        root = fors_node(sk_seed, pk_seed, adrs.copy(), i, params.a, params)
        expected_roots.extend(root)
    
    from src.algorithms.fips205.hash_functions import T_l
    pk_fors_expected = T_l(pk_seed, adrs_roots, expected_roots, n)
    
    # 1. Generate FORS signature
    sig_fors = fors_sign(md, sk_seed, pk_seed, adrs.copy(), params)
    
    # Check signature size is standard per FIPS 205 Eq: k * (1 + a) * n
    expected_sig_len = params.k * (1 + params.a) * n
    assert len(sig_fors) == expected_sig_len
    
    # 2. Reconstruct FORS PK from the signature
    pk_fors_recovered = fors_pkFromSig(sig_fors, md, pk_seed, adrs.copy(), params)

    # 3. Validation
    assert pk_fors_recovered == pk_fors_expected
