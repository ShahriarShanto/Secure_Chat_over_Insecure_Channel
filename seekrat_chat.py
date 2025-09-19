#!/usr/bin/env python3
"""
seekrat_chat.py

Simple script to do AES-256-GCM encrypted messaging between two parties over an
unsecure channel that only exchanges text files.

Behavior (per your spec):
1) If `encryption_key.txt` not found, script generates a random 6-digit Part A,
   prints it for you to share with Party B, and prompts for Party B's Part B.
   Part A and Part B are 6-digit strings; they can be entered in any order and
   the script will derive the same key on both sides.
   The two parts are combined deterministically (sorted and concatenated) and
   run through PBKDF2-HMAC-SHA256 to produce a 32-byte key. The derived key is
   saved (base64) in `encryption_key.txt` with restrictive permissions.
   If `encryption_key.txt` exists, it is used directly.

2) The script continuously monitors two files for changes:
   - A_message.txt : plaintext you write -> script encrypts to A_data.txt (BASE64)
   - B_data.txt     : encrypted BASE64 from party B -> script decrypts to B_message.txt

3) Encryption uses AES-256-GCM (authenticated). Each encrypted blob is nonce(12) || ciphertext+tag
   and saved as a single BASE64 string into A_data.txt.

Requirements:
  pip install cryptography

Security notes / caveats (read before use):
- Using two 6-digit numbers as shared secrets has very low entropy. This provides
  *limited* security and is vulnerable to brute-force if an attacker obtains the
  encrypted files and knows the key derivation algorithm. Use this only for
  low-risk experiments or add more entropy (longer secrets) if needed.
- The script uses a fixed PBKDF2 salt (deterministic) so both parties derive the
  same key. For stronger security, you should exchange a random salt out-of-band
  or store it in the key file, but keep in mind both ends must use the same salt.

Run:
  python secure_comm.py

"""

import base64
import os
import stat
import sys
import time
import json
import secrets
import hashlib
from getpass import getpass

try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception as e:
    sys.exit("Missing dependency: please install 'cryptography' (pip install cryptography)")


# -------- configuration --------
KEYFILE = "encryption_key.txt"
PART_A_DIGITS = 6
PBKDF2_SALT = b"random_salt_same_at_both_side"  # deterministic salt so both sides derive same key
PBKDF2_ITERATIONS = 200_000
KEY_LEN = 32  # 32 bytes = 256 bits
NONCE_LEN = 12  # recommended for AESGCM
POLL_INTERVAL = 0.8  # seconds between file checks

# file names used for exchange
A_MESSAGE = "A_message.txt"  # plaintext input (A -> encrypted)
A_DATA = "A_data.txt"        # encrypted BASE64 output
B_DATA = "B_data.txt"        # encrypted BASE64 input (from B)
B_MESSAGE = "B_message.txt"  # decrypted plaintext output (from B)


# -------- helpers --------

def save_key_to_file(key_bytes: bytes):
    b64 = base64.b64encode(key_bytes).decode("utf-8")
    with open(KEYFILE, "w", encoding="utf-8") as f:
        f.write(b64)
    # restrict permissions
    try:
        os.chmod(KEYFILE, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass


def load_key_from_file() -> bytes:
    with open(KEYFILE, "r", encoding="utf-8") as f:
        data = f.read().strip()
    return base64.b64decode(data)


def derive_key_from_parts(part_a: str, part_b: str) -> bytes:
    # Normalize parts to strings of digits and ensure they're 6-digit (zero-pad if needed)
    a = part_a.strip()
    b = part_b.strip()
    if not (a.isdigit() and b.isdigit()):
        raise ValueError("Both parts must be digit strings.")
    # make order-invariant by sorting the two parts
    s1, s2 = sorted([a, b])
    joined = (s1 + s2).encode("utf-8")
    # derive via PBKDF2-HMAC-SHA256
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=PBKDF2_SALT,
        iterations=PBKDF2_ITERATIONS,
    )
    key = kdf.derive(joined)
    return key


def generate_part_a() -> str:
    # 6-digit random number, zero-padded
    return f"{secrets.randbelow(10**PART_A_DIGITS):0{PART_A_DIGITS}d}"


def encrypt_and_write_a(plaintext: str, key: bytes):
    if plaintext is None or plaintext == "":
        return
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(NONCE_LEN)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    # store nonce || ct as base64
    blob = nonce + ct
    b64 = base64.b64encode(blob).decode("utf-8")
    with open(A_DATA, "w", encoding="utf-8") as f:
        f.write(b64)
    # set safe permissions
    try:
        os.chmod(A_DATA, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass


def decrypt_b_and_write_plain(b64blob: str, key: bytes):
    if b64blob is None or b64blob == "":
        return
    try:
        blob = base64.b64decode(b64blob)
        nonce = blob[:NONCE_LEN]
        ct = blob[NONCE_LEN:]
        aesgcm = AESGCM(key)
        pt = aesgcm.decrypt(nonce, ct, None)
        text = pt.decode("utf-8")
    except Exception as e:
        text = f"<decryption error: {e}>"
    with open(B_MESSAGE, "w", encoding="utf-8") as f:
        f.write(text)
    try:
        os.chmod(B_MESSAGE, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass


# -------- main flow --------

def ensure_key() -> bytes:
    if os.path.exists(KEYFILE):
        try:
            key = load_key_from_file()
            print(f"Loaded key from {KEYFILE} (using existing shared key).")
            return key
        except Exception as e:
            print("Failed to load key file, will regenerate:", e)

    # else: create
    part_a = generate_part_a()
    print("--- Key generation ---")
    print(f"Your Part A (share this with Party B): {part_a}")
    # read Part B from user input (hide input if wanted)
    # we use regular input so user can paste easily; they must enter the 6-digit code received.
    part_b = input("Enter Part B (6 digits) received from Party B: ").strip()
    if not (part_b.isdigit() and 1 <= len(part_b) <= 20):
        print("Warning: Part B should be numeric. Proceeding anyway.")
    try:
        key = derive_key_from_parts(part_a, part_b)
    except Exception as e:
        print("Failed to derive key:", e)
        sys.exit(1)
    save_key_to_file(key)
    print(f"Derived key saved to {KEYFILE}. Keep this file secret.")
    return key


def read_file_if_exists(path: str):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return None


def main_loop(key: bytes):
    print("Starting watch loop. Ctrl-C to exit.")
    # keep track of last-modified times and last processed contents to avoid loops
    last_mtime_a_msg = None
    last_mtime_b_data = None
    last_processed_a_message = None
    last_processed_b_blob = None

    while True:
        try:
            # A_message -> encrypt -> write A_data
            try:
                mtime_a = os.path.getmtime(A_MESSAGE)
            except Exception:
                mtime_a = None

            if mtime_a is not None and mtime_a != last_mtime_a_msg:
                last_mtime_a_msg = mtime_a
                plaintext = read_file_if_exists(A_MESSAGE) or ""
                if plaintext != last_processed_a_message:
                    encrypt_and_write_a(plaintext, key)
                    last_processed_a_message = plaintext
                    print(f"[{time.strftime('%H:%M:%S')}] Encrypted A_message.txt -> A_data.txt")

            # B_data -> decrypt -> write B_message
            try:
                mtime_b = os.path.getmtime(B_DATA)
            except Exception:
                mtime_b = None

            if mtime_b is not None and mtime_b != last_mtime_b_data:
                last_mtime_b_data = mtime_b
                blob = read_file_if_exists(B_DATA) or ""
                if blob != last_processed_b_blob:
                    decrypt_b_and_write_plain(blob, key)
                    last_processed_b_blob = blob
                    print(f"[{time.strftime('%H:%M:%S')}] Decrypted B_data.txt -> B_message.txt")

            time.sleep(POLL_INTERVAL)
        except KeyboardInterrupt:
            print("Exiting.")
            return
        except Exception as e:
            # do not crash -- print and continue
            print("Error in loop:", e)
            time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    key = ensure_key()
    main_loop(key)
