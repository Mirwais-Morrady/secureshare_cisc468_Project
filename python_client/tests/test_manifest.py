import sys
from pathlib import Path
import pytest
import base64

BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE_DIR))

from crypto.manifest import build_manifest, sign_manifest
from crypto.identity import IdentityManager


class TestManifest:

    def test_build_manifest_contains_required_fields(self, tmp_path):
        test_file = tmp_path / "test.txt"
        test_file.write_bytes(b"hello world")

        manifest = build_manifest("peer-id-123", "test-peer", test_file)
        assert manifest["file_name"] == "test.txt"
        assert manifest["file_size"] == 11
        assert "file_sha256_hex" in manifest
        assert len(manifest["file_sha256_hex"]) == 64
        assert manifest["owner_peer_id"] == "peer-id-123"
        assert manifest["owner_peer_name"] == "test-peer"
        assert manifest["manifest_version"] == "1.0"

    def test_build_manifest_correct_sha256(self, tmp_path):
        import hashlib
        content = b"test content for hashing"
        test_file = tmp_path / "test.txt"
        test_file.write_bytes(content)
        expected_hash = hashlib.sha256(content).hexdigest()

        manifest = build_manifest("pid", "peer", test_file)
        assert manifest["file_sha256_hex"] == expected_hash

    def test_sign_manifest_adds_signature(self, tmp_path):
        identity_dir = tmp_path / "identity"
        mgr = IdentityManager(identity_dir)
        identity = mgr.load_or_create_identity("test-peer")

        test_file = tmp_path / "file.txt"
        test_file.write_bytes(b"file content")
        manifest = build_manifest(identity.peer_id, identity.peer_name, test_file)
        signed = sign_manifest(identity.private_key, manifest)

        assert "signature_b64" in signed
        sig_bytes = base64.b64decode(signed["signature_b64"])
        assert len(sig_bytes) > 0

    def test_sign_manifest_signature_is_verifiable(self, tmp_path):
        from protocol.canonical_json import canonical_json_bytes

        identity_dir = tmp_path / "identity"
        mgr = IdentityManager(identity_dir)
        identity = mgr.load_or_create_identity("test-peer")

        test_file = tmp_path / "file.txt"
        test_file.write_bytes(b"file content")
        manifest = build_manifest(identity.peer_id, identity.peer_name, test_file)
        # sign_manifest mutates manifest in place, so make a copy for unsigned
        import copy
        manifest_copy = copy.deepcopy(manifest)
        signed = sign_manifest(identity.private_key, manifest_copy)

        # Rebuild the unsigned part for verification
        unsigned = {k: v for k, v in signed.items() if k != "signature_b64"}
        data = canonical_json_bytes(unsigned)
        sig = base64.b64decode(signed["signature_b64"])

        # Should not raise
        IdentityManager.verify(identity.public_key, data, sig)

    def test_build_manifest_file_size_accurate(self, tmp_path):
        content = b"x" * 10000
        test_file = tmp_path / "bigfile.bin"
        test_file.write_bytes(content)
        manifest = build_manifest("pid", "peer", test_file)
        assert manifest["file_size"] == 10000
