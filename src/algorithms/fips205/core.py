"""FIPS 205 (SLH-DSA) — Internal keygen / sign / verify.

Implements Algorithms 18-20 from FIPS 205 Section 9:
  - slh_keygen_internal  (Algorithm 18)
  - slh_sign_internal    (Algorithm 19)
  - slh_verify_internal  (Algorithm 20)

Reference
---------
NIST FIPS 205, Section 9 — "SLH-DSA Internal Operations".
"""

from __future__ import annotations

from typing import Tuple

from .address import ADRS
from .fors import fors_pkFromSig, fors_sign
from .hash_functions import H_msg, PRF_msg
from .parameters import SLHDSAParameters
from .xmss import ht_sign, ht_verify, xmss_node


def slh_keygen_internal(sk_seed: bytes, sk_prf: bytes, pk_seed: bytes, params: SLHDSAParameters) -> Tuple[bytes, bytes]:
    """Algorithm 18: Generate an SLH-DSA key pair."""
    adrs = ADRS()
    adrs.set_layer_address(params.d - 1)
    
    pk_root = xmss_node(sk_seed, pk_seed, adrs, 0, params.hp, params)
    
    sk = sk_seed + sk_prf + pk_seed + pk_root
    pk = pk_seed + pk_root
    
    return sk, pk


def slh_sign_internal(M: bytes, SK: bytes, params: SLHDSAParameters, addrnd: bytes | None = None) -> bytes:
    """Algorithm 19: Generate an SLH-DSA signature."""
    n = params.n
    
    sk_seed = SK[0 : n]
    sk_prf = SK[n : 2 * n]
    pk_seed = SK[2 * n : 3 * n]
    pk_root = SK[3 * n : 4 * n]
    
    if addrnd is None:
        addrnd = pk_seed
        
    R = PRF_msg(sk_prf, addrnd, M, n)
    digest = H_msg(R, pk_seed, pk_root, M, params.m)
    
    md_len = (params.k * params.a + 7) // 8
    md = digest[0 : md_len]
    
    tmp_idx_tree_len = (params.h - params.hp + 7) // 8
    tmp_idx_tree = digest[md_len : md_len + tmp_idx_tree_len]
    
    tmp_idx_leaf_len = (params.hp + 7) // 8
    tmp_idx_leaf = digest[md_len + tmp_idx_tree_len : md_len + tmp_idx_tree_len + tmp_idx_leaf_len]
    
    idx_tree = int.from_bytes(tmp_idx_tree, "big") % (1 << (params.h - params.hp))
    idx_leaf = int.from_bytes(tmp_idx_leaf, "big") % (1 << params.hp)
    
    adrs = ADRS()
    adrs.set_tree_address(idx_tree)
    adrs.set_type_and_clear(ADRS.FORS_TREE)
    adrs.set_key_pair_address(idx_leaf)
    
    sig_fors = fors_sign(md, sk_seed, pk_seed, adrs, params)
    pk_fors = fors_pkFromSig(sig_fors, md, pk_seed, adrs, params)
    
    sig_ht = ht_sign(pk_fors, sk_seed, pk_seed, idx_tree, idx_leaf, params)
    
    return R + sig_fors + sig_ht


def slh_verify_internal(M: bytes, SIG: bytes, PK: bytes, params: SLHDSAParameters) -> bool:
    """Algorithm 20: Verify an SLH-DSA signature."""
    n = params.n
    
    if len(SIG) != params.sig_bytes:
        return False
        
    pk_seed = PK[0 : n]
    pk_root = PK[n : 2 * n]
    
    R = SIG[0 : n]
    sig_fors_len = params.k * (1 + params.a) * n
    sig_fors = SIG[n : n + sig_fors_len]
    sig_ht = SIG[n + sig_fors_len : ]
    
    digest = H_msg(R, pk_seed, pk_root, M, params.m)
    
    md_len = (params.k * params.a + 7) // 8
    md = digest[0 : md_len]
    
    tmp_idx_tree_len = (params.h - params.hp + 7) // 8
    tmp_idx_tree = digest[md_len : md_len + tmp_idx_tree_len]
    
    tmp_idx_leaf_len = (params.hp + 7) // 8
    tmp_idx_leaf = digest[md_len + tmp_idx_tree_len : md_len + tmp_idx_tree_len + tmp_idx_leaf_len]
    
    idx_tree = int.from_bytes(tmp_idx_tree, "big") % (1 << (params.h - params.hp))
    idx_leaf = int.from_bytes(tmp_idx_leaf, "big") % (1 << params.hp)
    
    adrs = ADRS()
    adrs.set_tree_address(idx_tree)
    adrs.set_type_and_clear(ADRS.FORS_TREE)
    adrs.set_key_pair_address(idx_leaf)
    
    pk_fors = fors_pkFromSig(sig_fors, md, pk_seed, adrs, params)
    
    return ht_verify(pk_fors, sig_ht, pk_seed, idx_tree, idx_leaf, pk_root, params)
