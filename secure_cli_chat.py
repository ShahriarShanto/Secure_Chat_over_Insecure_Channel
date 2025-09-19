#!/usr/bin/env python3
"""
secure_cli_chat.py

- If "encryption_key.txt" exists in current directory, its base64 key is used.
- Otherwise: generate Part A (6 digits) and show to user, ask for Part B (6 digits).
  Combine Part A and Part B in an order-independent way to derive a key via PBKDF2-HMAC-SHA256.
  Save key (base64) to encryption_key.txt.
- Uses AES-256-GCM for encrypt/decrypt.
- Encryption: input plaintext (CLI) -> prints base64 of (nonce + ciphertext + tag).
- Decryption: input base64 -> prints plaintext.
- Loop: repeating encryption and decryption prompts. Press ENTER (empty input) to skip a step.
"""

import os
import base64
import getpass
import secrets
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---- Configuration (as requested: random salt hard-coded here) ----
# NOTICE: keep this script secret if you rely on the salt being secret.
_HARDCODED_SALT = b"random_salt_red_dragon_1337"
_PBKDF2_ITERATIONS = 200_000   # reasonable iteration count
_KEY_FILE = "encryption_key.txt"
_KEY_LEN = 32  # AES-256

# ---- Helpers ----
def save_key_to_file(key_bytes: bytes):
    with open(_KEY_FILE, "wb") as f:
        f.write(base64.b64encode(key_bytes))
    print(f"[+] Key saved to '{_KEY_FILE}' (base64).")

def load_key_from_file():
    if not os.path.exists(_KEY_FILE):
        return None
    with open(_KEY_FILE, "rb") as f:
        b64 = f.read().strip()
    try:
        key = base64.b64decode(b64)
    except Exception as e:
        raise RuntimeError(f"Failed reading key file: {e}")
    if len(key) != _KEY_LEN:
        raise RuntimeError(f"Key in {_KEY_FILE} has unexpected length {len(key)}.")
    return key

def derive_key_from_parts(part_a: str, part_b: str) -> bytes:
    """
    Combine part_a and part_b in an order-independent way and run PBKDF2.
    Combining strategy: lexicographically sort the two 6-digit strings and concat.
    """
    if not (part_a.isdigit() and part_b.isdigit() and len(part_a) == 6 and len(part_b) == 6):
        raise ValueError("Parts must be 6-digit numeric strings.")
    components = sorted([part_a, part_b])
    combined = (components[0] + components[1]).encode("utf-8")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_KEY_LEN,
        salt=_HARDCODED_SALT,
        iterations=_PBKDF2_ITERATIONS,
    )
    key = kdf.derive(combined)
    return key

def generate_part_a() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"

# ---- Encryption / Decryption ----
def encrypt_message(key: bytes, plaintext: bytes) -> bytes:
    # AESGCM expects 12-byte (96-bit) nonce for best interoperability
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    # Return nonce || ct
    return nonce + ct

def decrypt_message(key: bytes, data: bytes) -> bytes:
    if len(data) < 12 + 16:  # nonce + minimum tag/ciphertext
        raise ValueError("Ciphertext too short.")
    nonce = data[:12]
    ct = data[12:]
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, ct, associated_data=None)
    return pt

# ---- CLI Flow ----
def main():
    print("=== Secure CLI (AES-256-GCM) ===")
    key = None

    # 1) load or derive key
    key = load_key_from_file()
    if key:
        print(f"[+] Found existing key file '{_KEY_FILE}'. Using stored key.")
    else:
        print("[*] No key file found. Generating Part A and deriving key with Part B from the other party.")
        part_a = generate_part_a()
        print(f"[!] Your Part A (share this with Party B manually): {part_a}")
        # use getpass so an observer won't easily see when typing in some terminals, but it's fine either way
        while True:
            part_b = input("Enter Part B (6 digits) received from Party B: ").strip()
            if len(part_b) == 0:
                print("Part B input is required to derive the key. Try again.")
                continue
            if not (part_b.isdigit() and len(part_b) == 6):
                print("Part B must be exactly 6 digits. Try again.")
                continue
            try:
                key = derive_key_from_parts(part_a, part_b)
            except Exception as e:
                print(f"Failed to derive key: {e}")
                continue
            save_key_to_file(key)
            break

    # 2) main loop: keep repeating encryption and decryption steps. ENTER to skip a step.
    print("\nEntering encrypt/decrypt loop. Press Ctrl+C or type 'quit' at any input to exit.")
    try:
        while True:
            # Encryption step
            plaintext = input("\n[Encrypt] Enter plaintext to encrypt (ENTER to skip): ")
            if plaintext.lower() == "quit":
                print("Quitting.")
                return
            if plaintext != "":
                try:
                    ct_blob = encrypt_message(key, plaintext.encode("utf-8"))
                    b64 = base64.b64encode(ct_blob).decode("utf-8")
                    print("\n[Ciphertext - base64]")
                    print(b64)
                except Exception as e:
                    print(f"Encryption failed: {e}")
            else:
                print("[Encryption skipped]")

            # Decryption step
            enc_in = input("\n[Decrypt] Enter base64 ciphertext to decrypt (ENTER to skip): ")
            if enc_in.lower() == "quit":
                print("Quitting.")
                return
            if enc_in != "":
                try:
                    raw = base64.b64decode(enc_in)
                    pt = decrypt_message(key, raw)
                    try:
                        text = pt.decode("utf-8")
                        print("\n[Plaintext]")
                        print(text)
                    except UnicodeDecodeError:
                        # binary output fallback
                        print("\n[Plaintext - raw bytes]")
                        print(pt)
                except Exception as e:
                    print(f"Decryption failed: {e}")
            else:
                print("[Decryption skipped]")

    except KeyboardInterrupt:
        print("\nInterrupted. Exiting.")

if __name__ == "__main__":
    main()
