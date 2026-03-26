"""FIPS 205 (SLH-DSA) — XMSS and Hypertree.

Implements Algorithms 9-13 from FIPS 205 Sections 6 & 7:
  - xmss_node       (Algorithm 9)
  - xmss_sign       (Algorithm 10)
  - xmss_pkFromSig  (Algorithm 11)
  - ht_sign         (Algorithm 12)
  - ht_verify       (Algorithm 13)

Reference
---------
NIST FIPS 205, Sections 6 & 7 — "XMSS" and "Hypertree".
"""

from __future__ import annotations

from typing import List

from .address import ADRS
from .hash_functions import H
from .parameters import SLHDSAParameters
from .wots import wots_pkFromSig, wots_pkGen, wots_sign


def xmss_node(sk_seed: bytes, pk_seed: bytes, adrs: ADRS, i: int, z: int, params: SLHDSAParameters) -> bytes:
    """Algorithm 9: Compute the root of an XMSS subtree."""
    if z == 0:
        adrs.set_type_and_clear(ADRS.WOTS_HASH)
        adrs.set_key_pair_address(i)
        return wots_pkGen(sk_seed, pk_seed, adrs, params)
    else:
        lnode = xmss_node(sk_seed, pk_seed, adrs, 2 * i, z - 1, params)
        rnode = xmss_node(sk_seed, pk_seed, adrs, 2 * i + 1, z - 1, params)
        
        adrs_c = adrs.copy()
        adrs_c.set_type_and_clear(ADRS.TREE)
        
        adrs_c.set_tree_height(z)
        adrs_c.set_tree_index(i)
        
        return H(pk_seed, adrs_c, lnode + rnode, params.n)


def xmss_sign(M: bytes, sk_seed: bytes, idx: int, pk_seed: bytes, adrs: ADRS, params: SLHDSAParameters) -> bytes:
    """Algorithm 10: Generate an XMSS signature."""
    auth = bytearray()
    
    for j in range(params.hp):
        k = (idx >> j) ^ 1
        auth.extend(xmss_node(sk_seed, pk_seed, adrs.copy(), k, j, params))
        
    adrs_c = adrs.copy()
    adrs_c.set_type_and_clear(ADRS.WOTS_HASH)
    adrs_c.set_key_pair_address(idx)
    
    sig = wots_sign(M, sk_seed, pk_seed, adrs_c, params)
    return sig + bytes(auth)


def xmss_pkFromSig(idx: int, sig_xmss: bytes, M: bytes, pk_seed: bytes, adrs: ADRS, params: SLHDSAParameters) -> bytes:
    """Algorithm 11: Compute an XMSS public key from an XMSS signature."""
    sig_wots_len = params.length * params.n
    sig_wots = sig_xmss[0 : sig_wots_len]
    auth = sig_xmss[sig_wots_len : ]
    
    adrs_c = adrs.copy()
    adrs_c.set_type_and_clear(ADRS.WOTS_HASH)
    adrs_c.set_key_pair_address(idx)
    
    node = wots_pkFromSig(sig_wots, M, pk_seed, adrs_c, params)
    
    adrs_c = adrs.copy()
    adrs_c.set_type_and_clear(ADRS.TREE)
    adrs_c.set_tree_index(idx)
    
    for j in range(params.hp):
        auth_j = auth[j * params.n : (j + 1) * params.n]
        
        adrs_c.set_tree_height(j + 1)
        adrs_c.set_tree_index(idx >> (j + 1))
        
        if (idx >> j) & 1 == 0:
            node = H(pk_seed, adrs_c, node + auth_j, params.n)
        else:
            node = H(pk_seed, adrs_c, auth_j + node, params.n)
            
    return node


def ht_sign(M: bytes, sk_seed: bytes, pk_seed: bytes, idx_tree: int, idx_leaf: int, params: SLHDSAParameters) -> bytes:
    """Algorithm 12: Generate a hypertree signature."""
    adrs = ADRS()
    adrs.set_tree_address(idx_tree)
    adrs.set_layer_address(0)
    
    sig_tmp = xmss_sign(M, sk_seed, idx_leaf, pk_seed, adrs, params)
    sig_ht = bytearray(sig_tmp)
    
    root = xmss_pkFromSig(idx_leaf, sig_tmp, M, pk_seed, adrs, params)
    
    for j in range(1, params.d):
        idx_leaf = idx_tree % (1 << params.hp)
        idx_tree = idx_tree >> params.hp
        
        adrs.set_layer_address(j)
        adrs.set_tree_address(idx_tree)
        
        sig_tmp = xmss_sign(root, sk_seed, idx_leaf, pk_seed, adrs, params)
        sig_ht.extend(sig_tmp)
        
        if j < params.d - 1:
            root = xmss_pkFromSig(idx_leaf, sig_tmp, root, pk_seed, adrs, params)
            
    return bytes(sig_ht)


def ht_verify(M: bytes, sig_ht: bytes, pk_seed: bytes, idx_tree: int, idx_leaf: int, pk_root: bytes, params: SLHDSAParameters) -> bool:
    """Algorithm 13: Verify a hypertree signature."""
    adrs = ADRS()
    adrs.set_tree_address(idx_tree)
    adrs.set_layer_address(0)
    
    xmss_sig_len = (params.length + params.hp) * params.n
    sig_tmp = sig_ht[0 : xmss_sig_len]
    
    node = xmss_pkFromSig(idx_leaf, sig_tmp, M, pk_seed, adrs, params)
    
    for j in range(1, params.d):
        idx_leaf = idx_tree % (1 << params.hp)
        idx_tree = idx_tree >> params.hp
        
        adrs.set_layer_address(j)
        adrs.set_tree_address(idx_tree)
        
        sig_tmp = sig_ht[j * xmss_sig_len : (j + 1) * xmss_sig_len]
        node = xmss_pkFromSig(idx_leaf, sig_tmp, node, pk_seed, adrs, params)
        
    return node == pk_root
