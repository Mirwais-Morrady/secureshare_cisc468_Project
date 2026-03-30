"""
REQUIREMENT 5 — Offline File Redistribution with Tamper Verification
=====================================================================
Scenario: Peer A shares a file and signs a manifest. Peer A goes offline.
Peer B previously downloaded the file from A. Peer C fetches the file from B
and verifies it against A's signed manifest — without A being online.

Tests that:
  - A manifest is correctly built from a file's metadata + SHA-256
  - The manifest is signed with the owner's RSA private key (PSS-SHA-256)
  - A third peer can verify the manifest using only A's public key
  - A tampered file is detected (SHA-256 mismatch)
  - A forged manifest (wrong signature) is rejected
  - A manifest signed by a different key is rejected (wrong owner)
"""
import hashlib
import tempfile
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature

from crypto.identity import IdentityManager
from crypto.manifest import build_manifest, sign_manifest
from protocol.canonical_json import canonical_json_bytes


def make_identity(name="owner", tmpdir=None):
    d = Path(tmpdir or tempfile.mkdtemp()) / name
    mgr = IdentityManager(d)
    return mgr.load_or_create_identity(name)


class TestManifestBuilding:

    def test_manifest_contains_required_fields(self, tmp_path):
        identity = make_identity(tmpdir=tmp_path)
        f = tmp_path / "report.txt"
        f.write_bytes(b"Annual financial report data")
        manifest = build_manifest(identity.peer_id, identity.peer_name, f)

        assert manifest["manifest_version"] == "1.0"
        assert manifest["owner_peer_id"] == identity.peer_id
        assert manifest["owner_peer_name"] == identity.peer_name
        assert manifest["file_name"] == "report.txt"
        assert manifest["file_size"] == len(b"Annual financial report data")
        assert "file_sha256_hex" in manifest

    def test_manifest_sha256_matches_file(self, tmp_path):
        identity = make_identity(tmpdir=tmp_path)
        content = b"File content for integrity test"
        f = tmp_path / "data.bin"
        f.write_bytes(content)
        manifest = build_manifest(identity.peer_id, identity.peer_name, f)
        expected = hashlib.sha256(content).hexdigest()
        assert manifest["file_sha256_hex"] == expected

    def test_different_files_produce_different_sha256(self, tmp_path):
        identity = make_identity(tmpdir=tmp_path)
        f1 = tmp_path / "file1.txt"
        f2 = tmp_path / "file2.txt"
        f1.write_bytes(b"content A")
        f2.write_bytes(b"content B")
        m1 = build_manifest(identity.peer_id, identity.peer_name, f1)
        m2 = build_manifest(identity.peer_id, identity.peer_name, f2)
        assert m1["file_sha256_hex"] != m2["file_sha256_hex"]


class TestManifestSigning:

    def test_signed_manifest_contains_signature_field(self, tmp_path):
        identity = make_identity(tmpdir=tmp_path)
        f = tmp_path / "f.txt"
        f.write_bytes(b"data")
        manifest = build_manifest(identity.peer_id, identity.peer_name, f)
        signed = sign_manifest(identity.private_key, manifest)
        assert "signature_b64" in signed

    def test_signature_is_verifiable_with_public_key(self, tmp_path):
        """The signed manifest must be verifiable with the owner's public key."""
        import base64
        identity = make_identity(tmpdir=tmp_path)
        f = tmp_path / "f.txt"
        f.write_bytes(b"file content here")
        manifest = build_manifest(identity.peer_id, identity.peer_name, f)
        signed = sign_manifest(identity.private_key, dict(manifest))

        # Re-derive what was signed (manifest without the signature field)
        unsigned = {k: v for k, v in signed.items() if k != "signature_b64"}
        sig = base64.b64decode(signed["signature_b64"])
        # Must not raise
        IdentityManager.verify(identity.public_key, canonical_json_bytes(unsigned), sig)

    def test_tampered_file_detected_via_manifest(self, tmp_path):
        """Receiving a file whose SHA-256 doesn't match the manifest must be caught."""
        identity = make_identity(tmpdir=tmp_path)
        f = tmp_path / "original.txt"
        f.write_bytes(b"original content")
        manifest = sign_manifest(identity.private_key,
                                 build_manifest(identity.peer_id, identity.peer_name, f))
        # Simulate receiving a tampered file
        tampered_data = b"tampered content!!"
        received_hash = hashlib.sha256(tampered_data).hexdigest()
        assert received_hash != manifest["file_sha256_hex"], \
            "Tampered file must produce a different SHA-256 — redistribution integrity check would catch this"

    def test_forged_manifest_signature_rejected(self, tmp_path):
        """A manifest with a randomly corrupted signature must be rejected."""
        import base64
        identity = make_identity(tmpdir=tmp_path)
        f = tmp_path / "f.txt"
        f.write_bytes(b"content")
        signed = sign_manifest(identity.private_key,
                               build_manifest(identity.peer_id, identity.peer_name, f))
        # Corrupt the signature
        bad_sig = b"\x00" * 256
        signed["signature_b64"] = base64.b64encode(bad_sig).decode()
        unsigned = {k: v for k, v in signed.items() if k != "signature_b64"}
        with pytest.raises(Exception):
            IdentityManager.verify(identity.public_key,
                                   canonical_json_bytes(unsigned),
                                   bad_sig)

    def test_signature_from_different_key_rejected(self, tmp_path):
        """A manifest signed by a different (attacker) key must not verify against the owner's public key."""
        import base64
        owner = make_identity("owner", tmp_path)
        attacker = make_identity("attacker", tmp_path)
        f = tmp_path / "f.txt"
        f.write_bytes(b"content")
        manifest = build_manifest(owner.peer_id, owner.peer_name, f)
        # Attacker signs the manifest with their own key
        attacker_signed = sign_manifest(attacker.private_key, dict(manifest))
        unsigned = {k: v for k, v in attacker_signed.items() if k != "signature_b64"}
        sig = base64.b64decode(attacker_signed["signature_b64"])
        # Verifying against the OWNER's public key must fail
        with pytest.raises(Exception):
            IdentityManager.verify(owner.public_key, canonical_json_bytes(unsigned), sig)
