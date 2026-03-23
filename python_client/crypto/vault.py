
import os, base64, json
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


ITER = 200000


def derive_key(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITER,
    )
    return kdf.derive(password.encode())


def encrypt_bytes(data: bytes, password: str):
    salt = os.urandom(16)
    nonce = os.urandom(12)

    key = derive_key(password, salt)
    aes = AESGCM(key)
    ct = aes.encrypt(nonce, data, None)

    return {
        "salt_b64": base64.b64encode(salt).decode(),
        "nonce_b64": base64.b64encode(nonce).decode(),
        "ciphertext_b64": base64.b64encode(ct).decode(),
    }


# Format: 16-byte salt || 12-byte nonce || ciphertext (includes 16-byte GCM tag)
def encrypt_vault(password: str, plaintext: bytes) -> bytes:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(password, salt)
    aes = AESGCM(key)
    ct = aes.encrypt(nonce, plaintext, None)
    return salt + nonce + ct


def decrypt_vault(password: str, data: bytes) -> bytes:
    salt = data[:16]
    nonce = data[16:28]
    ct = data[28:]
    key = derive_key(password, salt)
    aes = AESGCM(key)
    return aes.decrypt(nonce, ct, None)
