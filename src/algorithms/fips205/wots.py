"""FIPS 205 (SLH-DSA) — WOTS+ one-time signature scheme.

Implements Algorithms 4-8 from FIPS 205 Section 5:
  - base_2b       (Algorithm 4)
  - chain         (Algorithm 5)
  - wots_pkGen    (Algorithm 6)
  - wots_sign     (Algorithm 7)
  - wots_pkFromSig (Algorithm 8)

Reference
---------
NIST FIPS 205, Section 5 — "WOTS+ One-Time Signatures".
"""

from __future__ import annotations

import math
from typing import List

from .address import ADRS
from .hash_functions import F, PRF, T_l
from .parameters import SLHDSAParameters


def base_2b(X: bytes, b: int, out_len: int) -> List[int]:
    """Algorithm 4: Base-2b representation.
    
    Computes the base-2^b representation of X.
    """
    in_idx = 0
    bits = 0
    total = 0
    res = []
    
    mask = (1 << b) - 1
    
    for _ in range(out_len):
        while bits < b:
            if in_idx < len(X):
                total = (total << 8) | X[in_idx]
                in_idx += 1
                bits += 8
            else:
                # Pad with zeros if we run out of input
                total = total << 8
                bits += 8
                
        bits -= b
        res.append((total >> bits) & mask)
        
    return res


def chain(X: bytes, i: int, s: int, pk_seed: bytes, adrs: ADRS, n: int) -> bytes:
    """Algorithm 5: Chaining function.
    
    Applies the hash function F iteratively `s` times starting from index `i`.
    """
    if s == 0:
        return X
        
    if i + s > (1 << 4) - 1:  # w - 1 where w=16
        raise ValueError("Chain out of bounds")
        
    tmp = X
    for j in range(i, i + s):
        adrs.set_hash_address(j)
        tmp = F(pk_seed, adrs, tmp, n)
        
    return tmp


def wots_pkGen(sk_seed: bytes, pk_seed: bytes, adrs: ADRS, params: SLHDSAParameters) -> bytes:
    """Algorithm 6: Generate a WOTS+ public key.
    
    Returns a single `n`-byte hash representing the public key.
    """
    adrs_c = adrs.copy()
    
    # Generate secret key chains using PRF
    sk_chains = []
    adrs_c.set_type_and_clear(ADRS.WOTS_PRF)
    kp_addr = adrs._a[20:24]
    
    # We must explicitly set key pair address if copying cleared it, but 
    # set_type_and_clear zeros bytes 20-31, so we need to copy it back or set it.
    kp_addr = adrs._a[20:24]
    
    adrs_c.set_type_and_clear(ADRS.WOTS_PRF)
    adrs_c._a[20:24] = kp_addr  # Restore key pair address
    
    for i in range(params.length):
        adrs_c.set_chain_address(i)
        sk_chains.append(PRF(pk_seed, sk_seed, adrs_c, params.n))
        
    # Generate public key chains using F
    pk_chains = []
    adrs_c.set_type_and_clear(ADRS.WOTS_HASH)
    adrs_c._a[20:24] = kp_addr
    
    for i in range(params.length):
        adrs_c.set_chain_address(i)
        pk_chains.append(chain(sk_chains[i], 0, params.w - 1, pk_seed, adrs_c, params.n))
        
    # Compress all chain endpoints into a single public key using T_l
    adrs_c.set_type_and_clear(ADRS.WOTS_PK)
    adrs_c._a[20:24] = kp_addr
    
    pk_concat = b''.join(pk_chains)
    return T_l(pk_seed, adrs_c, pk_concat, params.n)


def wots_sign(M: bytes, sk_seed: bytes, pk_seed: bytes, adrs: ADRS, params: SLHDSAParameters) -> bytes:
    """Algorithm 7: Generate a WOTS+ signature on a message M."""
    csum = 0
    msg = base_2b(M, params.lg_w, params.len1)
    
    for i in range(params.len1):
        csum += params.w - 1 - msg[i]
        
    # Convert checksum to bytes and append
    csum_bytes = csum.to_bytes(math.ceil(params.len2 * params.lg_w / 8.0), 'big')
    msg.extend(base_2b(csum_bytes, params.lg_w, params.len2))
    
    adrs_c = adrs.copy()
    kp_addr = adrs._a[20:24]
    
    sig = bytearray()
    
    for i in range(params.length):
        adrs_c.set_type_and_clear(ADRS.WOTS_PRF)
        adrs_c._a[20:24] = kp_addr
        adrs_c.set_chain_address(i)
        
        sk = PRF(pk_seed, sk_seed, adrs_c, params.n)
        
        adrs_c.set_type_and_clear(ADRS.WOTS_HASH)
        adrs_c._a[20:24] = kp_addr
        adrs_c.set_chain_address(i)
        
        sig.extend(chain(sk, 0, msg[i], pk_seed, adrs_c, params.n))
        
    return bytes(sig)


def wots_pkFromSig(sig: bytes, M: bytes, pk_seed: bytes, adrs: ADRS, params: SLHDSAParameters) -> bytes:
    """Algorithm 8: Compute a WOTS+ public key from a message and its signature."""
    csum = 0
    msg = base_2b(M, params.lg_w, params.len1)
    
    for i in range(params.len1):
        csum += params.w - 1 - msg[i]
        
    csum_bytes = csum.to_bytes(math.ceil(params.len2 * params.lg_w / 8.0), 'big')
    msg.extend(base_2b(csum_bytes, params.lg_w, params.len2))
    
    adrs_c = adrs.copy()
    kp_addr = adrs._a[20:24]
    
    tmp = []
    
    adrs_c.set_type_and_clear(ADRS.WOTS_HASH)
    adrs_c._a[20:24] = kp_addr
    
    for i in range(params.length):
        adrs_c.set_chain_address(i)
        sig_i = sig[i * params.n : (i + 1) * params.n]
        tmp.append(chain(sig_i, msg[i], params.w - 1 - msg[i], pk_seed, adrs_c, params.n))
        
    # Compress chains back to public key
    adrs_c.set_type_and_clear(ADRS.WOTS_PK)
    adrs_c._a[20:24] = kp_addr
    
    pk_concat = b''.join(tmp)
    return T_l(pk_seed, adrs_c, pk_concat, params.n)
