"""FIPS 205 (SLH-DSA) — ADRS address structure.

Manages the 32-byte address (ADRS) used to domain-separate every hash
invocation in SLH-DSA. Address type constants and getter/setter methods
follow FIPS 205 Table 1.

Reference
---------
NIST FIPS 205, Section 4, Table 1 — "ADRS byte layout".
"""

from __future__ import annotations

class ADRS:
    """32-byte address structure used across all SLH-DSA hash function calls."""
    
    # Address types (FIPS 205 Table 3)
    WOTS_HASH  = 0
    WOTS_PK    = 1
    TREE       = 2
    FORS_TREE  = 3
    FORS_ROOTS = 4
    WOTS_PRF   = 5
    FORS_PRF   = 6

    def __init__(self, initial_bytes: bytes | bytearray | None = None) -> None:
        if initial_bytes is not None:
            if len(initial_bytes) != 32:
                raise ValueError("ADRS must be initialized with exactly 32 bytes.")
            self._a = bytearray(initial_bytes)
        else:
            self._a = bytearray(32)

    def copy(self) -> ADRS:
        """Return a deep copy of this address structure."""
        return ADRS(self._a)

    def to_bytes(self) -> bytes:
        """Return the immutable 32-byte snapshot of this address."""
        return bytes(self._a)

    # -------------------------------------------------------------------------
    # Setters mapping to byte layout (FIPS 205 Table 1)
    # Fields are big-endian unsigned integers.
    # -------------------------------------------------------------------------

    def set_layer_address(self, layer: int) -> None:
        """Bytes [0..3]: Layer address."""
        self._a[0:4] = layer.to_bytes(4, 'big')

    def set_tree_address(self, tree: int) -> None:
        """Bytes [4..15]: Tree address (8 bytes or 12 bytes; FIPS 205 specifies 12)."""
        self._a[4:16] = tree.to_bytes(12, 'big')

    def set_type_and_clear(self, addr_type: int) -> None:
        """Bytes [16..19]: Type. Also clears bytes [20..31] to zero."""
        self._a[16:20] = addr_type.to_bytes(4, 'big')
        self._a[20:32] = b'\x00' * 12

    def set_key_pair_address(self, i: int) -> None:
        """Bytes [20..23]: Key pair address (used in WOTS+ and XMSS)."""
        self._a[20:24] = i.to_bytes(4, 'big')

    def set_chain_address(self, i: int) -> None:
        """Bytes [24..27]: Chain address (used in WOTS+)."""
        self._a[24:28] = i.to_bytes(4, 'big')

    def set_hash_address(self, i: int) -> None:
        """Bytes [28..31]: Hash address (used in WOTS+)."""
        self._a[28:32] = i.to_bytes(4, 'big')

    def set_tree_height(self, h: int) -> None:
        """Bytes [24..27]: Tree height (used in Trees). Shares memory with chain address."""
        self._a[24:28] = h.to_bytes(4, 'big')

    def set_tree_index(self, i: int) -> None:
        """Bytes [28..31]: Tree index (used in Trees). Shares memory with hash address."""
        self._a[28:32] = i.to_bytes(4, 'big')
