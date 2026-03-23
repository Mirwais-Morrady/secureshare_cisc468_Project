import sys
from pathlib import Path
import pytest

BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE_DIR))

from crypto.vault import encrypt_vault, decrypt_vault


class TestVault:

    def test_encrypt_decrypt_roundtrip(self):
        password = "test-password"
        plaintext = b"secret vault data"
        encrypted = encrypt_vault(password, plaintext)
        decrypted = decrypt_vault(password, encrypted)
        assert decrypted == plaintext

    def test_different_passwords_fail(self):
        password = "correct-password"
        wrong_password = "wrong-password"
        plaintext = b"vault secret"
        encrypted = encrypt_vault(password, plaintext)
        with pytest.raises(Exception):
            decrypt_vault(wrong_password, encrypted)

    def test_encrypted_data_is_different_from_plaintext(self):
        password = "password"
        plaintext = b"plaintext data"
        encrypted = encrypt_vault(password, plaintext)
        assert encrypted != plaintext

    def test_same_plaintext_different_ciphertext(self):
        password = "password"
        plaintext = b"data"
        enc1 = encrypt_vault(password, plaintext)
        enc2 = encrypt_vault(password, plaintext)
        # Each encryption should produce different output (random nonce/salt)
        assert enc1 != enc2

    def test_encrypt_returns_bytes(self):
        encrypted = encrypt_vault("pwd", b"data")
        assert isinstance(encrypted, bytes)

    def test_large_plaintext(self):
        password = "password"
        plaintext = b"x" * 100000
        encrypted = encrypt_vault(password, plaintext)
        decrypted = decrypt_vault(password, encrypted)
        assert decrypted == plaintext
