"""FIPS 205 (SLH-DSA) — FORS few-time signature scheme.

Implements Algorithms 14-17 from FIPS 205 Section 8:
  - fors_skGen      (Algorithm 14)
  - fors_node       (Algorithm 15)
  - fors_sign       (Algorithm 16)
  - fors_pkFromSig  (Algorithm 17)

Reference
---------
NIST FIPS 205, Section 8 — "Forest of Random Subsets (FORS)".
"""

from __future__ import annotations

from typing import List

from .address import ADRS
from .hash_functions import F, H, PRF, T_l
from .parameters import SLHDSAParameters
from .wots import base_2b


def fors_skGen(sk_seed: bytes, pk_seed: bytes, adrs: ADRS, idx: int, params: SLHDSAParameters) -> bytes:
    """Algorithm 14: Generate a FORS private key value."""
    adrs_c = adrs.copy()
    tree_addr = adrs._a[4:16]  # Preserve tree address
    kp_addr = adrs._a[20:24]   # Preserve key pair address
    
    adrs_c.set_type_and_clear(ADRS.FORS_PRF)
    adrs_c._a[4:16] = tree_addr
    adrs_c._a[20:24] = kp_addr
    
    adrs_c.set_tree_index(idx)
    return PRF(pk_seed, sk_seed, adrs_c, params.n)


def fors_node(sk_seed: bytes, pk_seed: bytes, adrs: ADRS, i: int, z: int, params: SLHDSAParameters) -> bytes:
    """Algorithm 15: Compute the root of a FORS subtree."""
    if z == 0:
        sk = fors_skGen(sk_seed, pk_seed, adrs, i, params)
        
        adrs_c = adrs.copy()
        tree_addr = adrs._a[4:16]
        kp_addr = adrs._a[20:24]
        
        adrs_c.set_type_and_clear(ADRS.FORS_TREE)
        adrs_c._a[4:16] = tree_addr
        adrs_c._a[20:24] = kp_addr
        
        adrs_c.set_tree_height(0)
        adrs_c.set_tree_index(i)
        
        return F(pk_seed, adrs_c, sk, params.n)
        
    else:
        lnode = fors_node(sk_seed, pk_seed, adrs, 2 * i, z - 1, params)
        rnode = fors_node(sk_seed, pk_seed, adrs, 2 * i + 1, z - 1, params)
        
        adrs_c = adrs.copy()
        tree_addr = adrs._a[4:16]
        kp_addr = adrs._a[20:24]
        
        adrs_c.set_type_and_clear(ADRS.FORS_TREE)
        adrs_c._a[4:16] = tree_addr
        adrs_c._a[20:24] = kp_addr
        
        adrs_c.set_tree_height(z)
        adrs_c.set_tree_index(i)
        
        return H(pk_seed, adrs_c, lnode + rnode, params.n)


def fors_sign(md: bytes, sk_seed: bytes, pk_seed: bytes, adrs: ADRS, params: SLHDSAParameters) -> bytes:
    """Algorithm 16: Generate a FORS signature."""
    sig = bytearray()
    indices = base_2b(md, params.a, params.k)
    
    for i in range(params.k):
        global_idx = i * (1 << params.a) + indices[i]
        
        # 1. Provide secret key leaf
        sig.extend(fors_skGen(sk_seed, pk_seed, adrs, global_idx, params))
        
        # 2. Provide authentication path
        for j in range(params.a):
            sibling_idx = (indices[i] >> j) ^ 1
            node_idx = i * (1 << (params.a - j)) + sibling_idx
            sig.extend(fors_node(sk_seed, pk_seed, adrs, node_idx, j, params))
            
    return bytes(sig)


def fors_pkFromSig(sig: bytes, md: bytes, pk_seed: bytes, adrs: ADRS, params: SLHDSAParameters) -> bytes:
    """Algorithm 17: Compute a FORS public key from a signature."""
    indices = base_2b(md, params.a, params.k)
    roots = []
    
    # Each FORS tree signature segment is: SK leaf (n bytes) + auth path (a * n bytes)
    sig_len_per_tree = (params.a + 1) * params.n
    
    for i in range(params.k):
        tree_sig = sig[i * sig_len_per_tree : (i + 1) * sig_len_per_tree]
        sk_leaf = tree_sig[0 : params.n]
        auth_path = tree_sig[params.n : sig_len_per_tree]
        
        # Compute leaf at height 0
        adrs_c = adrs.copy()
        tree_addr = adrs._a[4:16]
        kp_addr = adrs._a[20:24]
        
        adrs_c.set_type_and_clear(ADRS.FORS_TREE)
        adrs_c._a[4:16] = tree_addr
        adrs_c._a[20:24] = kp_addr
        
        adrs_c.set_tree_height(0)
        global_idx = i * (1 << params.a) + indices[i]
        adrs_c.set_tree_index(global_idx)
        
        node = F(pk_seed, adrs_c, sk_leaf, params.n)
        
        # Reconstruct tree up to root
        for j in range(params.a):
            auth_node = auth_path[j * params.n : (j + 1) * params.n]
            
            adrs_c.set_tree_height(j + 1)
            adrs_c.set_tree_index(global_idx >> (j + 1))
            
            if (indices[i] >> j) & 1 == 0:
                node = H(pk_seed, adrs_c, node + auth_node, params.n)
            else:
                node = H(pk_seed, adrs_c, auth_node + node, params.n)
                
        roots.append(node)
        
    adrs_c = adrs.copy()
    tree_addr = adrs._a[4:16]
    kp_addr = adrs._a[20:24]
    
    adrs_c.set_type_and_clear(ADRS.FORS_ROOTS)
    adrs_c._a[4:16] = tree_addr
    adrs_c._a[20:24] = kp_addr
    
    return T_l(pk_seed, adrs_c, b''.join(roots), params.n)
