"""
Tests for encrypted local file storage (Requirement 9).

Files stored in the vault are encrypted with AES-256-GCM using a key
derived from a user password via PBKDF2-HMAC-SHA-256 (200,000 iterations).
An attacker who steals the device cannot read the files without the password.
"""
import sys
from pathlib import Path
import pytest

BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE_DIR))

from storage.vault_store import VaultStore


class TestVaultStore:

    def test_store_and_retrieve(self, tmp_path):
        vault = VaultStore(tmp_path, password="password123")
        vault.store_file("hello.txt", b"hello world")
        result = vault.get_file("hello.txt")
        assert result == b"hello world"

    def test_stored_file_is_encrypted_on_disk(self, tmp_path):
        vault = VaultStore(tmp_path, password="password123")
        vault.store_file("secret.txt", b"top secret data")

        enc_path = tmp_path / "secret.txt.enc"
        assert enc_path.exists()
        raw = enc_path.read_bytes()
        assert b"top secret data" not in raw

    def test_wrong_password_raises(self, tmp_path):
        vault = VaultStore(tmp_path, password="correct")
        vault.store_file("f.txt", b"data")
        wrong = VaultStore(tmp_path, password="wrong")
        with pytest.raises(Exception):
            wrong.get_file("f.txt")

    def test_list_files(self, tmp_path):
        vault = VaultStore(tmp_path, password="pw")
        vault.store_file("a.txt", b"aaa")
        vault.store_file("b.txt", b"bbb")
        files = vault.list_files()
        assert "a.txt" in files
        assert "b.txt" in files

    def test_has_file(self, tmp_path):
        vault = VaultStore(tmp_path, password="pw")
        assert not vault.has_file("x.txt")
        vault.store_file("x.txt", b"data")
        assert vault.has_file("x.txt")

    def test_delete_file(self, tmp_path):
        vault = VaultStore(tmp_path, password="pw")
        vault.store_file("del.txt", b"data")
        vault.delete_file("del.txt")
        assert not vault.has_file("del.txt")

    def test_store_large_file(self, tmp_path):
        vault = VaultStore(tmp_path, password="pw")
        data = b"x" * 500_000
        vault.store_file("big.bin", data)
        result = vault.get_file("big.bin")
        assert result == data

    def test_get_nonexistent_raises(self, tmp_path):
        vault = VaultStore(tmp_path, password="pw")
        with pytest.raises(FileNotFoundError):
            vault.get_file("does_not_exist.txt")
