"""
REQUIREMENT 6 — Key Migration (Compromised Key Notification)
=============================================================
Tests that:
  - A peer can build a KEY_MIGRATION message signed by both old and new keys
  - Contacts can verify the migration using only the old (trusted) public key
  - The migration message contains the new public key and peer identity
  - A forged migration (signed with unknown key) is rejected
  - A replay of an old migration (wrong old_peer_id) is rejected
  - After migration, contacts should use the new public key going forward
"""
import base64
import tempfile
from pathlib import Path

import pytest

from crypto.identity import IdentityManager
from crypto.key_migration import build_key_migration_message, verify_key_migration


def make_identity(name, base_dir):
    d = Path(base_dir) / name
    mgr = IdentityManager(d)
    return mgr.load_or_create_identity(name)


class TestKeyMigrationBuild:

    def test_migration_message_contains_required_fields(self, tmp_path):
        old_id = make_identity("old_alice", tmp_path)
        new_id = make_identity("new_alice", tmp_path)
        msg = build_key_migration_message(old_id, new_id)

        assert msg["type"] == "KEY_MIGRATION"
        assert msg["proto_ver"] == "1.0"
        assert msg["old_peer_id"] == old_id.peer_id
        assert msg["new_peer_id"] == new_id.peer_id
        assert msg["new_peer_name"] == new_id.peer_name
        assert "new_rsa_public_key_der_b64" in msg
        assert "old_key_signature_b64" in msg
        assert "new_key_signature_b64" in msg

    def test_migration_message_embeds_new_public_key(self, tmp_path):
        old_id = make_identity("old_peer", tmp_path)
        new_id = make_identity("new_peer", tmp_path)
        msg = build_key_migration_message(old_id, new_id)
        # The embedded new public key must match the actual new identity's key
        embedded = base64.b64decode(msg["new_rsa_public_key_der_b64"])
        assert embedded == new_id.public_key_der

    def test_old_peer_id_differs_from_new_peer_id(self, tmp_path):
        old_id = make_identity("old_p", tmp_path)
        new_id = make_identity("new_p", tmp_path)
        msg = build_key_migration_message(old_id, new_id)
        assert msg["old_peer_id"] != msg["new_peer_id"], \
            "Old and new peer IDs must be different (different RSA keys)"


class TestKeyMigrationVerification:

    def test_valid_migration_verifies_successfully(self, tmp_path):
        old_id = make_identity("alice_old", tmp_path)
        new_id = make_identity("alice_new", tmp_path)
        msg = build_key_migration_message(old_id, new_id)
        # A contact that trusts old_id verifies using old public key
        new_peer_id, new_pub_b64 = verify_key_migration(msg, old_id.public_key)
        assert new_peer_id == new_id.peer_id
        assert new_pub_b64 == base64.b64encode(new_id.public_key_der).decode()

    def test_forged_migration_from_unknown_key_rejected(self, tmp_path):
        """An attacker who doesn't own the old key cannot forge a migration."""
        old_id = make_identity("victim", tmp_path)
        attacker_old = make_identity("attacker_old", tmp_path)
        attacker_new = make_identity("attacker_new", tmp_path)
        # Attacker builds a migration claiming to be the victim
        forged = build_key_migration_message(attacker_old, attacker_new)
        forged["old_peer_id"] = old_id.peer_id  # spoof the peer ID
        # Verification against the real victim's public key must fail
        with pytest.raises(Exception):
            verify_key_migration(forged, old_id.public_key)

    def test_tampered_migration_message_rejected(self, tmp_path):
        """Modifying any field of the migration message must break the signature."""
        old_id = make_identity("bob_old", tmp_path)
        new_id = make_identity("bob_new", tmp_path)
        msg = build_key_migration_message(old_id, new_id)
        # Tamper: change the new_peer_name after signing
        msg["new_peer_name"] = "attacker-controlled-name"
        with pytest.raises(Exception):
            verify_key_migration(msg, old_id.public_key)

    def test_missing_field_raises_value_error(self, tmp_path):
        """A migration message missing required fields must raise ValueError."""
        old_id = make_identity("carol_old", tmp_path)
        new_id = make_identity("carol_new", tmp_path)
        msg = build_key_migration_message(old_id, new_id)
        del msg["old_key_signature_b64"]
        with pytest.raises(ValueError, match="missing required field"):
            verify_key_migration(msg, old_id.public_key)

    def test_wrong_message_type_raises_value_error(self, tmp_path):
        old_id = make_identity("dan_old", tmp_path)
        new_id = make_identity("dan_new", tmp_path)
        msg = build_key_migration_message(old_id, new_id)
        msg["type"] = "FAKE_TYPE"
        with pytest.raises(ValueError, match="not KEY_MIGRATION"):
            verify_key_migration(msg, old_id.public_key)

    def test_verified_migration_provides_new_public_key(self, tmp_path):
        """After verification, the returned new public key must be usable for crypto."""
        old_id = make_identity("eve_old", tmp_path)
        new_id = make_identity("eve_new", tmp_path)
        msg = build_key_migration_message(old_id, new_id)
        _, new_pub_b64 = verify_key_migration(msg, old_id.public_key)

        # Load the returned key and use it to verify a signature made by new_id
        from cryptography.hazmat.primitives import serialization
        new_pub = serialization.load_der_public_key(base64.b64decode(new_pub_b64))
        test_data = b"post-migration secure message"
        sig = IdentityManager.sign(new_id.private_key, test_data)
        IdentityManager.verify(new_pub, test_data, sig)  # must not raise
