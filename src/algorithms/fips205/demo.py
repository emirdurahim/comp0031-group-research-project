import time
import sys
import argparse
import binascii
from pathlib import Path

# Ensure the 'src' module can be imported when running this from anywhere
sys.path.append(str(Path(__file__).resolve().parents[3]))

try:
    from src.algorithms.fips205 import SLH_DSA
except ImportError:
    print("Error: Could not import SLH_DSA. Make sure you are running this from the repository root.")
    sys.exit(1)

def main():
    print("="*60)
    print(" NIST FIPS 205 (SLH-DSA) Interactive Demonstration ")
    print("="*60)
    print("\nNote: FIPS 205 is a Digital Signature Algorithm. It does not 'encrypt' messages,")
    print("but rather generates a cryptographic signature to guarantee authenticity.\n")
    
    # Prompt the user
    try:
        message_str = input("Enter a message to sign: ")
    except EOFError:
        message_str = "Default message"
        
    print(f"\n[!] Message received: '{message_str}'")
    message_bytes = message_str.encode('utf-8')
    
    # Initialize the fast variant for demo purposes (the 's' variants are very slow in pure Python)
    param_set = "SLH-DSA-SHAKE-128f"
    print(f"\n[1] Initializing Parameter Set: {param_set}...")
    alg = SLH_DSA(parameter_set=param_set)
    
    print("[2] Generating Keypair (Please wait... this can take a few seconds)...")
    start = time.time()
    kp = alg.keygen()
    print(f"    -> Keypair generated in {time.time() - start:.2f}s.")
    print(f"    -> Public Key size: {len(kp.public_key)} bytes")
    print(f"    -> Secret Key size: {len(kp.secret_key)} bytes")
    
    print("\n[3] Signing the message...")
    start = time.time()
    signature = alg.sign(kp.secret_key, message_bytes)
    print(f"    -> Message signed in {time.time() - start:.2f}s.")
    
    # Display the signature
    sig_hex = binascii.hexlify(signature).decode('utf-8')
    print("\n" + "-"*60)
    print(f"Generated Signature (Hex, {len(signature)} bytes):")
    if len(sig_hex) > 150:
        print(f"{sig_hex[:75]}\n...\n{sig_hex[-75:]}")
    else:
        print(sig_hex)
    print("-"*60)
    
    print("\n[4] Verifying the signature authenticity...")
    start = time.time()
    is_valid = alg.verify(kp.public_key, message_bytes, signature)
    print(f"    -> Mathematically verified in {time.time() - start:.4f}s.")
    
    print("\n" + "="*60)
    if is_valid:
        print("✅ SUCCESS: The signature is VALID. Message authenticity is guaranteed.")
    else:
        print("❌ FAILED: The signature is INVALID.")
    print("="*60)

if __name__ == "__main__":
    main()
