"""
REQUIREMENT 9 — Secure Local Storage (Encrypted Vault)
=======================================================
Tests that:
  - Files stored in the vault are encrypted on disk (unreadable without password)
  - Correct password decrypts successfully
  - Wrong password is rejected (InvalidTag — AEAD authentication failure)
  - Tampered vault data is detected
  - Each encryption of the same file produces a different ciphertext (random salt + nonce)
  - VaultStore correctly persists, lists, retrieves and deletes files
  - PBKDF2-HMAC-SHA256 with 200,000 iterations is used (key stretching)
"""
import os
import tempfile
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from crypto.vault import encrypt_vault, decrypt_vault, ITER
from storage.vault_store import VaultStore


# ── Low-level vault crypto ────────────────────────────────────────────────────

class TestVaultCrypto:

    def test_encrypt_decrypt_roundtrip(self):
        """Encrypting then decrypting with the same password recovers original data."""
        password = "correct-horse-battery-staple"
        plaintext = b"This is a confidential file."
        blob = encrypt_vault(password, plaintext)
        assert decrypt_vault(password, blob) == plaintext

    def test_encrypted_blob_does_not_contain_plaintext(self):
        """Ciphertext must not contain the plaintext (basic confidentiality check)."""
        password = "mypassword"
        plaintext = b"supersecret document contents"
        blob = encrypt_vault(password, plaintext)
        assert plaintext not in blob, "Plaintext must not appear in the encrypted blob"

    def test_wrong_password_rejected(self):
        """Decrypting with a different password must raise an authentication error."""
        blob = encrypt_vault("correct-password", b"secret")
        with pytest.raises(Exception):  # InvalidTag from AESGCM
            decrypt_vault("wrong-password", blob)

    def test_tampered_blob_detected(self):
        """Flipping a byte in the ciphertext region must raise an error."""
        blob = bytearray(encrypt_vault("password", b"data"))
        blob[30] ^= 0xFF   # ciphertext starts at byte 28 (16 salt + 12 nonce)
        with pytest.raises(Exception):
            decrypt_vault("password", bytes(blob))

    def test_different_encryptions_produce_different_blobs(self):
        """Random salt and nonce mean the same plaintext never encrypts identically."""
        password = "same-password"
        plaintext = b"identical content"
        blob1 = encrypt_vault(password, plaintext)
        blob2 = encrypt_vault(password, plaintext)
        assert blob1 != blob2, "Each encryption must be unique (random salt + nonce)"

    def test_blob_format_salt_nonce_ciphertext(self):
        """Blob must be at least 16 (salt) + 12 (nonce) + 16 (GCM tag) = 44 bytes."""
        blob = encrypt_vault("password", b"")
        assert len(blob) >= 44, f"Blob too short: {len(blob)} bytes"

    def test_iterations_constant_is_200000(self):
        """PBKDF2 iteration count must be 200,000 for adequate key stretching."""
        assert ITER == 200_000, f"Expected 200000 iterations, got {ITER}"

    def test_large_file_roundtrip(self):
        """A 1 MB file must survive encrypt→decrypt intact."""
        plaintext = os.urandom(1024 * 1024)
        blob = encrypt_vault("strongpassword", plaintext)
        assert decrypt_vault("strongpassword", blob) == plaintext


# ── VaultStore (file-system level) ───────────────────────────────────────────

class TestVaultStore:

    def setup_method(self):
        self._tmpdir = tempfile.mkdtemp()
        self.vault = VaultStore(Path(self._tmpdir), password="testpassword123")

    def test_store_and_retrieve_file(self):
        """Storing then retrieving a file must return the original bytes."""
        original = b"Confidential report contents"
        self.vault.store_file("report.txt", original)
        retrieved = self.vault.get_file("report.txt")
        assert retrieved == original

    def test_file_on_disk_is_encrypted(self):
        """The .enc file on disk must not contain the plaintext."""
        plaintext = b"Do not read this without decryption"
        self.vault.store_file("secret.txt", plaintext)
        enc_path = Path(self._tmpdir) / "secret.txt.enc"
        assert enc_path.exists(), ".enc file must be created on disk"
        raw = enc_path.read_bytes()
        assert plaintext not in raw, "Plaintext must not appear in the .enc file"

    def test_list_files(self):
        """list_files() must return the names of all stored files."""
        self.vault.store_file("a.txt", b"aaa")
        self.vault.store_file("b.txt", b"bbb")
        files = self.vault.list_files()
        assert "a.txt" in files
        assert "b.txt" in files

    def test_delete_file(self):
        """delete_file() must remove the file from storage and the index."""
        self.vault.store_file("temp.txt", b"temporary")
        self.vault.delete_file("temp.txt")
        assert "temp.txt" not in self.vault.list_files()
        assert not (Path(self._tmpdir) / "temp.txt.enc").exists()

    def test_wrong_password_on_retrieve(self):
        """A VaultStore with the wrong password must fail on get_file()."""
        self.vault.store_file("locked.txt", b"contents")
        wrong_vault = VaultStore(Path(self._tmpdir), password="wrong-password")
        with pytest.raises(Exception):
            wrong_vault.get_file("locked.txt")

    def test_overwrite_updates_contents(self):
        """Storing the same filename again must update the stored content."""
        self.vault.store_file("doc.txt", b"version 1")
        self.vault.store_file("doc.txt", b"version 2")
        assert self.vault.get_file("doc.txt") == b"version 2"

    def test_empty_vault_list_files_returns_empty(self):
        """A new vault must report no files."""
        assert self.vault.list_files() == []
