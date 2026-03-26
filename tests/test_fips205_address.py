import pytest
from src.algorithms.fips205.address import ADRS

def test_adrs_initialization():
    adrs = ADRS()
    assert len(adrs.to_bytes()) == 32
    assert adrs.to_bytes() == b'\x00' * 32

    # Initializing with bytes
    init_bytes = b'\x01' * 32
    adrs2 = ADRS(init_bytes)
    assert adrs2.to_bytes() == init_bytes

    with pytest.raises(ValueError):
        ADRS(b'\x01' * 31)

def test_set_layer_address():
    adrs = ADRS()
    adrs.set_layer_address(0x12345678)
    b = adrs.to_bytes()
    assert b[0:4] == bytes([0x12, 0x34, 0x56, 0x78])
    assert b[4:] == b'\x00' * 28

def test_set_tree_address():
    adrs = ADRS()
    adrs.set_tree_address(0x0102030405060708090a0b0c)
    b = adrs.to_bytes()
    assert b[4:16] == bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c])

def test_set_type_and_clear():
    adrs = ADRS()
    # Set garbage in the back part to test clear
    adrs.set_key_pair_address(0xFFFFFFFF)
    adrs.set_chain_address(0xFFFFFFFF)
    adrs.set_hash_address(0xFFFFFFFF)
    
    adrs.set_type_and_clear(ADRS.WOTS_HASH)
    b = adrs.to_bytes()
    assert b[16:20] == bytes([0x00, 0x00, 0x00, 0x00]) # WOTS_HASH is 0
    assert b[20:32] == b'\x00' * 12

    adrs.set_type_and_clear(ADRS.FORS_PRF)
    b = adrs.to_bytes()
    assert b[16:20] == bytes([0x00, 0x00, 0x00, 0x06]) # FORS_PRF is 6
    assert b[20:32] == b'\x00' * 12

def test_set_key_pair_address():
    adrs = ADRS()
    adrs.set_key_pair_address(0xaabbccdd)
    b = adrs.to_bytes()
    assert b[20:24] == bytes([0xaa, 0xbb, 0xcc, 0xdd])

def test_set_chain_and_tree_height_address():
    adrs = ADRS()
    adrs.set_chain_address(0x11223344)
    b = adrs.to_bytes()
    assert b[24:28] == bytes([0x11, 0x22, 0x33, 0x44])

    adrs.set_tree_height(0x55667788)
    b = adrs.to_bytes()
    assert b[24:28] == bytes([0x55, 0x66, 0x77, 0x88])

def test_set_hash_and_tree_index_address():
    adrs = ADRS()
    adrs.set_hash_address(0x99aabbcc)
    b = adrs.to_bytes()
    assert b[28:32] == bytes([0x99, 0xaa, 0xbb, 0xcc])

    adrs.set_tree_index(0xddeeff00)
    b = adrs.to_bytes()
    assert b[28:32] == bytes([0xdd, 0xee, 0xff, 0x00])

def test_copy():
    adrs = ADRS()
    adrs.set_layer_address(0x01)
    
    adrs_copy = adrs.copy()
    assert adrs.to_bytes() == adrs_copy.to_bytes()

    # ensure it's a deep copy
    adrs_copy.set_layer_address(0x02)
    assert adrs.to_bytes()[0:4] == bytes([0x00, 0x00, 0x00, 0x01])
    assert adrs_copy.to_bytes()[0:4] == bytes([0x00, 0x00, 0x00, 0x02])
