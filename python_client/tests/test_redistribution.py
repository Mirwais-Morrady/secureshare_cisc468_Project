"""
Tests for offline redistribution with tamper verification (Requirement 5).

Scenario: Peer A is offline. Peer B already has A's file list and manifest.
Peer B finds Peer C who has the file, downloads from C, and verifies
the file matches A's signed manifest.

The manifest contains: filename, file_size, SHA-256 hash, signed by A's RSA key.
Peer B verifies: the SHA-256 of the downloaded file must match the manifest.
Any tampering by C is detected.
"""
import sys
import hashlib
from pathlib import Path
import pytest
import base64

BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE_DIR))

from crypto.identity import IdentityManager
from crypto.manifest import build_manifest, sign_manifest
from protocol.canonical_json import canonical_json_bytes


class TestManifestCreation:

    def test_manifest_contains_sha256_hash(self, tmp_path):
        identity = IdentityManager(tmp_path / "id").load_or_create_identity("alice")
        f = tmp_path / "file.txt"
        f.write_bytes(b"original content")

        manifest = build_manifest(identity.peer_id, identity.peer_name, f)
        signed = sign_manifest(identity.private_key, manifest.copy())

        assert "file_sha256_hex" in signed
        assert len(signed["file_sha256_hex"]) == 64

    def test_manifest_sha256_matches_file(self, tmp_path):
        identity = IdentityManager(tmp_path / "id").load_or_create_identity("alice")
        content = b"exact file bytes"
        f = tmp_path / "file.txt"
        f.write_bytes(content)
        expected_sha256 = hashlib.sha256(content).hexdigest()

        manifest = build_manifest(identity.peer_id, identity.peer_name, f)
        assert manifest["file_sha256_hex"] == expected_sha256


class TestRedistributionTamperDetection:

    def test_valid_file_passes_manifest_check(self, tmp_path):
        """A file downloaded from a third party that matches the manifest is accepted."""
        identity = IdentityManager(tmp_path / "id").load_or_create_identity("alice")
        original_content = b"original file content from peer A"
        f = tmp_path / "original.txt"
        f.write_bytes(original_content)

        manifest = build_manifest(identity.peer_id, identity.peer_name, f)
        signed = sign_manifest(identity.private_key, manifest.copy())

        # Simulate downloading the file from peer C
        downloaded_content = original_content  # C served the file correctly
        actual_sha256 = hashlib.sha256(downloaded_content).hexdigest()

        # Verify integrity
        assert actual_sha256 == signed["file_sha256_hex"], "Valid file should pass integrity check"

    def test_tampered_file_fails_manifest_check(self, tmp_path):
        """A tampered file must be detected via SHA-256 mismatch."""
        identity = IdentityManager(tmp_path / "id").load_or_create_identity("alice")
        original_content = b"original file content"
        f = tmp_path / "original.txt"
        f.write_bytes(original_content)

        manifest = build_manifest(identity.peer_id, identity.peer_name, f)
        signed = sign_manifest(identity.private_key, manifest.copy())

        # Simulate C tampering with the file
        tampered_content = b"THIS FILE HAS BEEN MODIFIED BY ATTACKER"
        actual_sha256 = hashlib.sha256(tampered_content).hexdigest()

        # Must fail
        assert actual_sha256 != signed["file_sha256_hex"], "Tampered file must fail integrity check"

    def test_manifest_signature_is_verifiable(self, tmp_path):
        """The manifest signature allows verifying the manifest came from peer A."""
        identity = IdentityManager(tmp_path / "id").load_or_create_identity("alice")
        f = tmp_path / "file.txt"
        f.write_bytes(b"data")

        manifest = build_manifest(identity.peer_id, identity.peer_name, f)
        signed = sign_manifest(identity.private_key, manifest.copy())

        # Re-verify the signature (as peer B would)
        sig = base64.b64decode(signed["signature_b64"])
        unsigned = {k: v for k, v in signed.items() if k != "signature_b64"}
        # Should not raise
        IdentityManager.verify(identity.public_key, canonical_json_bytes(unsigned), sig)

    def test_forged_manifest_is_rejected(self, tmp_path):
        """A manifest claiming to be from A but signed by attacker must be rejected."""
        from cryptography.exceptions import InvalidSignature

        alice = IdentityManager(tmp_path / "alice").load_or_create_identity("alice")
        attacker = IdentityManager(tmp_path / "attacker").load_or_create_identity("attacker")

        f = tmp_path / "file.txt"
        f.write_bytes(b"malicious content")

        # Attacker builds a manifest claiming to be alice but signs with their own key
        manifest = build_manifest(alice.peer_id, "alice", f)
        forged = sign_manifest(attacker.private_key, manifest.copy())

        sig = base64.b64decode(forged["signature_b64"])
        unsigned = {k: v for k, v in forged.items() if k != "signature_b64"}

        # Verification with alice's public key must fail
        with pytest.raises(Exception):
            IdentityManager.verify(alice.public_key, canonical_json_bytes(unsigned), sig)

    def test_tampered_manifest_is_rejected(self, tmp_path):
        """A manifest whose SHA-256 field was changed after signing must be rejected."""
        from cryptography.exceptions import InvalidSignature

        identity = IdentityManager(tmp_path / "id").load_or_create_identity("alice")
        f = tmp_path / "file.txt"
        f.write_bytes(b"data")

        manifest = build_manifest(identity.peer_id, identity.peer_name, f)
        signed = sign_manifest(identity.private_key, manifest.copy())

        # Attacker changes the hash in the manifest
        signed["file_sha256_hex"] = "a" * 64

        sig = base64.b64decode(signed["signature_b64"])
        unsigned = {k: v for k, v in signed.items() if k != "signature_b64"}

        with pytest.raises(Exception):
            IdentityManager.verify(identity.public_key, canonical_json_bytes(unsigned), sig)
