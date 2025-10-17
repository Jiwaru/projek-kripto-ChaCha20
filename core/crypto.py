# image_encryptor/core/crypto.py

import hashlib
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

def read_binary_file(file_path):
    """Reads the entire content of a file in binary mode."""
    with open(file_path, 'rb') as f:
        return f.read()

def write_binary_file(file_path, data):
    """Writes a bytes object to a file in binary mode."""
    with open(file_path, 'wb') as f:
        f.write(data)

def derive_key_from_password(password):
    """Derives a 32-byte key from the user's password using SHA-256."""
    return hashlib.sha256(password.encode()).digest()

def encrypt_image(file_path, key, output_path):
    """Encrypts a file using ChaCha20 and saves it."""
    plaintext = read_binary_file(file_path)
    nonce = get_random_bytes(12)
    cipher = ChaCha20.new(key=key, nonce=nonce)
    ciphertext = cipher.encrypt(plaintext)
    encrypted_data = nonce + ciphertext
    write_binary_file(output_path, encrypted_data)

def decrypt_image(encrypted_file_path, key, output_path):
    """Decrypts a file encrypted with ChaCha20, saves it, and returns the data."""
    encrypted_data = read_binary_file(encrypted_file_path)
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    cipher = ChaCha20.new(key=key, nonce=nonce)
    decrypted_data = cipher.decrypt(ciphertext)
    write_binary_file(output_path, decrypted_data)
    return decrypted_data