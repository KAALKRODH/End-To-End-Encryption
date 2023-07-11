import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

# Key generation and management


def generate_symmetric_key():
    return os.urandom(32)  # 32 bytes for AES-256


def generate_asymmetric_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def encrypt_symmetric_key(symmetric_key, public_key):
    encrypted_key = public_key.encrypt(
        symmetric_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key


def decrypt_symmetric_key(encrypted_key, private_key):
    decrypted_key = private_key.decrypt(
        encrypted_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_key

# Encryption and Decryption


def encrypt(plaintext, symmetric_key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(symmetric_key),
                    modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return iv + ciphertext


def decrypt(ciphertext, symmetric_key):
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(symmetric_key),
                    modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext


# Example Usage
symmetric_key = generate_symmetric_key()
private_key, public_key = generate_asymmetric_keypair()

plaintext = input("Enter the plaintext: ").encode()

encrypted_key = encrypt_symmetric_key(symmetric_key, public_key)
encrypted_text = encrypt(plaintext, symmetric_key)

decrypted_key = decrypt_symmetric_key(encrypted_key, private_key)
decrypted_text = decrypt(encrypted_text, decrypted_key)

print("Plain text:", plaintext.decode())
print("Encrypted text:", encrypted_text)
