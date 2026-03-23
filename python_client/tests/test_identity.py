import sys
from pathlib import Path
import pytest
import tempfile

BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE_DIR))

from crypto.identity import IdentityManager, Identity


class TestIdentity:

    def test_generate_identity_creates_keys(self, tmp_path):
        mgr = IdentityManager(tmp_path)
        identity = mgr.load_or_create_identity("test-peer")
        assert isinstance(identity, Identity)
        assert identity.peer_name == "test-peer"
        assert len(identity.peer_id) == 64  # SHA-256 hex = 64 chars
        assert identity.private_key is not None
        assert identity.public_key is not None
        assert len(identity.public_key_der) > 0

    def test_identity_persists_to_disk(self, tmp_path):
        mgr = IdentityManager(tmp_path)
        identity1 = mgr.load_or_create_identity("test-peer")
        identity2 = mgr.load_or_create_identity("test-peer")
        assert identity1.peer_id == identity2.peer_id

    def test_sign_and_verify_roundtrip(self, tmp_path):
        mgr = IdentityManager(tmp_path)
        identity = mgr.load_or_create_identity("test-peer")
        data = b"test data to sign"
        sig = IdentityManager.sign(identity.private_key, data)
        # Should not raise
        IdentityManager.verify(identity.public_key, data, sig)

    def test_sign_produces_nonempty_signature(self, tmp_path):
        mgr = IdentityManager(tmp_path)
        identity = mgr.load_or_create_identity("test-peer")
        sig = IdentityManager.sign(identity.private_key, b"data")
        assert len(sig) > 0

    def test_verify_rejects_wrong_data(self, tmp_path):
        from cryptography.exceptions import InvalidSignature
        mgr = IdentityManager(tmp_path)
        identity = mgr.load_or_create_identity("test-peer")
        sig = IdentityManager.sign(identity.private_key, b"correct data")
        with pytest.raises(Exception):
            IdentityManager.verify(identity.public_key, b"wrong data", sig)

    def test_peer_id_is_sha256_of_public_key_der(self, tmp_path):
        import hashlib
        mgr = IdentityManager(tmp_path)
        identity = mgr.load_or_create_identity("test-peer")
        expected = hashlib.sha256(identity.public_key_der).hexdigest()
        assert identity.peer_id == expected

    def test_fingerprint_equals_peer_id(self, tmp_path):
        mgr = IdentityManager(tmp_path)
        identity = mgr.load_or_create_identity("test-peer")
        assert identity.fingerprint_hex == identity.peer_id
