# Secure_Chat_over_Insecure_Channel
Encrypt and decrypt messages via CLI to chat with someone securely

# 🔒 Secure Chat Scripts

This repository contains two experimental Python tools for **AES-256-GCM encrypted messaging**.  
All code was written by **GPT-5**.

---

## 📂 Scripts

### 1. `secure_cli_chat.py` (Main Tool)
A command-line program for manual encryption and decryption.

- **Key exchange**: Both parties generate/share 6-digit codes (Part A and Part B).  
  These are combined (order-independent) and processed with **PBKDF2-HMAC-SHA256** to create a 256-bit key.  
- The derived key is stored in `encryption_key.txt` (Base64).
- Interactive CLI loop:
  - Enter plaintext → get Base64 ciphertext.
  - Enter Base64 ciphertext → get plaintext.

Run:
```bash
python secure_cli_chat.py
````

---

### 2. `seekrat_chat.py`

A file-based encrypted chat for two parties using a shared folder or exchange of text files.

* Files used:

  * `A_message.txt` → encrypted → `A_data.txt`
  * `B_data.txt` (from partner) → decrypted → `B_message.txt`
* Uses the same **two-part key derivation** as above.
* Continuously monitors files and updates outputs when changes are detected.

---
