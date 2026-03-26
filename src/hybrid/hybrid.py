import hashlib
from src.algorithms.fips203 import ML_KEM
from src.qkd_simulation.bb84 import BB84
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import hashlib
import hmac
import binascii


def aes_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce, tag, ciphertext


def aes_decrypt(key: bytes, nonce: bytes, tag: bytes, ciphertext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext


def bits_to_bytes(bits: list[int]) -> bytes:
    result = [0] * ((len(alice_sifted_bits) + 7) // 8)
    for i in range(len(bits)):
        result[i // 8] |= bits[i] << (i % 8)
    return bytes(result)


pqc = ML_KEM()
qkd = BB84()

# PQC key exchange
pqc_keys = pqc.keygen()
ek = pqc_keys.public_key
dk = pqc_keys.secret_key
alice_sk, c = pqc.encapsulate(ek)
bob_sk = pqc.decapsulate(dk, c)
alice_sk = bytes(alice_sk)
bob_sk = bytes(bob_sk)
assert alice_sk == bob_sk

# QKD send and measure qubits
alice_bits, alice_bases, alice_qubits = qkd.generate_qubits(256)
bob_bases, bob_bits = qkd.measure_qubits(alice_qubits)

# QKD sifting

## Exchanging Bases
### Alice encode bases with AES and send to Bob
alice_sift_key = SHA256.new(alice_sk + bytes("sift", "ascii")).digest()
bob_sift_key = SHA256.new(bob_sk + bytes("sift", "ascii")).digest()
alice_nonce, alice_tag, alice_ciphertext = aes_encrypt(
    alice_sift_key, bytes(alice_bases)
)
bob_alice_bases = aes_decrypt(bob_sift_key, alice_nonce, alice_tag, alice_ciphertext)
bob_alice_bases = list(bob_alice_bases)
assert alice_bases == bob_alice_bases
### Bob encode bases with AES and send to Alice
bob_nonce, bob_tag, bob_ciphertext = aes_encrypt(bob_sift_key, bytes(bob_bases))
alice_bob_bases = aes_decrypt(alice_sift_key, bob_nonce, bob_tag, bob_ciphertext)
alice_bob_bases = list(alice_bob_bases)
assert bob_bases == alice_bob_bases

## Sifting
alice_sifted_bits = qkd.sifting(alice_bases, alice_bob_bases, alice_bits)
bob_sifted_bits = qkd.sifting(bob_bases, bob_alice_bases, bob_bits)

## QBER
alice_indices, alice_qner_bits = qkd.initiate_qber(alice_sifted_bits)
alice_qber_key = SHA256.new(alice_sk + bytes("qber", "ascii")).digest()
bob_qber_key = SHA256.new(alice_sk + bytes("qber", "ascii")).digest()
alice_qber_nonce, alice_qber_tag, alice_qber_ciphertext = aes_encrypt(
    alice_qber_key, bytes(alice_indices + alice_qner_bits)
)
bob_alice_qber_plaintext = aes_decrypt(
    bob_qber_key, alice_qber_nonce, alice_qber_tag, alice_qber_ciphertext
)
bob_alice_qber_plaintext = list(bob_alice_qber_plaintext)
bob_alice_qber_indices = list(bob_alice_qber_plaintext)[
    : len(bob_alice_qber_plaintext) // 2
]
bob_alice_qber_bits = list(bob_alice_qber_plaintext)[
    len(bob_alice_qber_plaintext) // 2 :
]
assert bob_alice_qber_bits == alice_qner_bits
if qkd.check_qber(bob_sifted_bits, bob_alice_qber_bits, bob_alice_qber_indices):
    print("QBER Passed, continue")
else:
    print("QBER Failed, abort")

alice_qkd_key = bits_to_bytes(alice_sifted_bits)
bob_qkd_key = bits_to_bytes(bob_sifted_bits)


def hybrid_kdf(pqc_secret, qkd_secret, salt=b"", info=b"hybrid-key-v1"):
    # 1. Concatenate the secrets
    combined_input = pqc_secret + qkd_secret
    # 2. Extract: Bind the input to a fixed-length pseudorandom key (PRK)
    prk = hmac.new(salt, combined_input, hashlib.sha256).digest()
    # 3. Expand: Generate the final 256-bit AES key
    # (Simplified HKDF-Expand logic)
    final_key = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    return final_key


alice_final_key = hybrid_kdf(
    alice_sk, alice_qkd_key + bytes("final", encoding="ascii"), b"salt"
)
bob_final_key = hybrid_kdf(
    bob_sk, bob_qkd_key + bytes("final", encoding="ascii"), b"salt"
)

assert alice_final_key == bob_final_key
print(
    f"Alice Key: {binascii.hexlify(alice_final_key)}",
)
print(f"Bob Key: {binascii.hexlify(bob_final_key)}")
