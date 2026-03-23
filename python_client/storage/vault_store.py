"""
Encrypted file vault storage.

Files stored here are encrypted with AES-256-GCM using a key derived from
a user password via PBKDF2-HMAC-SHA-256 (200,000 iterations).
An attacker who steals the device cannot read vault files without the password.
"""
import json
import os
from pathlib import Path
from crypto.vault import encrypt_vault, decrypt_vault


class VaultStore:
    """
    Stores files encrypted at rest using a password-derived key.

    Each file is stored as: <vault_dir>/<filename>.enc
    The format is: salt(16) || nonce(12) || AES-GCM-ciphertext
    """

    def __init__(self, vault_dir: Path, password: str = "default-vault-password"):
        self.vault_dir = Path(vault_dir)
        self.password = password
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        # Index maps filename -> encrypted filename on disk
        self._index_path = self.vault_dir / "index.json"

    def store_file(self, filename: str, data: bytes):
        """
        Encrypt and store a file in the vault.

        Args:
            filename: The logical filename (as the peer shared it)
            data: Raw file bytes
        """
        encrypted = encrypt_vault(self.password, data)
        enc_path = self.vault_dir / (filename + ".enc")
        enc_path.write_bytes(encrypted)
        self._update_index(filename, filename + ".enc")

    def get_file(self, filename: str) -> bytes:
        """
        Retrieve and decrypt a file from the vault.

        Args:
            filename: The logical filename

        Returns:
            bytes: Decrypted file data

        Raises:
            FileNotFoundError: If the file is not in the vault
            Exception: If decryption fails (wrong password or tampered data)
        """
        enc_path = self.vault_dir / (filename + ".enc")
        if not enc_path.exists():
            raise FileNotFoundError(f"File '{filename}' not found in vault")
        encrypted = enc_path.read_bytes()
        return decrypt_vault(self.password, encrypted)

    def list_files(self) -> list:
        """Return list of filenames stored in the vault."""
        index = self._load_index()
        return list(index.keys())

    def has_file(self, filename: str) -> bool:
        """Check if a file exists in the vault."""
        return (self.vault_dir / (filename + ".enc")).exists()

    def delete_file(self, filename: str):
        """Delete a file from the vault."""
        enc_path = self.vault_dir / (filename + ".enc")
        if enc_path.exists():
            enc_path.unlink()
        index = self._load_index()
        index.pop(filename, None)
        self._save_index(index)

    def _load_index(self) -> dict:
        if not self._index_path.exists():
            return {}
        return json.loads(self._index_path.read_text())

    def _save_index(self, index: dict):
        self._index_path.write_text(json.dumps(index, indent=2))

    def _update_index(self, filename: str, enc_filename: str):
        index = self._load_index()
        index[filename] = enc_filename
        self._save_index(index)
