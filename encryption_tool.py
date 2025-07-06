# encryption_tool.py

"""
Advanced File Encryption Tool using AES-256
Author: Aditi Goel
Internship Task 4 - Secure file encryption/decryption
"""

import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64
import getpass

# --- Key Generation Function ---
def generate_key(password: str, salt: bytes) -> bytes:
    """
    Derives a secure 256-bit AES key from the password using PBKDF2 and salt.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes = 256 bits
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# --- Encrypt File Function ---
def encrypt_file(filepath, password):
    with open(filepath, 'rb') as f:
        data = f.read()

    salt = os.urandom(16)  # generate a random salt
    key = generate_key(password, salt)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data)

    filename = os.path.basename(filepath)
    output_path = f'encrypted_files/encrypted_{filename}'

    with open(output_path, 'wb') as f:
        f.write(salt + encrypted)  # prepend salt to encrypted data

    print(f"[+] File encrypted and saved to: {output_path}")

# --- Decrypt File Function ---
def decrypt_file(filepath, password):
    with open(filepath, 'rb') as f:
        data = f.read()

    salt = data[:16]  # extract the first 16 bytes as salt
    encrypted = data[16:]  # remaining is actual encrypted data
    key = generate_key(password, salt)
    fernet = Fernet(key)

    try:
        decrypted = fernet.decrypt(encrypted)
        filename = os.path.basename(filepath).replace('encrypted_', 'decrypted_')
        output_path = f'test_files/{filename}'

        with open(output_path, 'wb') as f:
            f.write(decrypted)

        print(f"[✓] File decrypted and saved to: {output_path}")

    except Exception as e:
        print("[!] Decryption failed. Wrong password or file corrupted.")
        print("Error:", e)

# --- Main Menu Function ---
def main():
    print("\n=== AES-256 Encryption Tool ===")
    print("1. Encrypt a file")
    print("2. Decrypt a file")
    print("0. Exit")

    choice = input("\nEnter your choice: ")

    if choice == '1':
        filepath = input("Enter path to file to encrypt: ")
        password = getpass.getpass("Enter password to encrypt: ")
        encrypt_file(filepath, password)

    elif choice == '2':
        filepath = input("Enter path to file to decrypt: ")
        password = getpass.getpass("Enter password to decrypt: ")
        decrypt_file(filepath, password)

    elif choice == '0':
        print("Exiting...")

    else:
        print("Invalid choice. Try again.")

# Run only if this file is executed directly
if __name__ == "__main__":
    main()

