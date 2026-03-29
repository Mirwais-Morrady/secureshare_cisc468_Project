"""
Tests for key migration protocol (Requirement 6).

When a peer's RSA key is compromised, they must:
  1. Generate a new RSA key pair.
  2. Build a KEY_MIGRATION message signed with the OLD key.
  3. Send it to all known contacts.
  4. Contacts verify using the already-trusted old public key,
     then update their contact record with the new public key.
"""
import sys
from pathlib import Path
import pytest
import base64

BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE_DIR))

from crypto.identity import IdentityManager
from storage.pending_migration_store import PendingMigrationStore

from crypto.key_migration import (
    build_key_migration_message,
    verify_key_migration,
    generate_new_identity,
)

class TestKeyMigration:

    def test_build_migration_message_has_required_fields(self, tmp_path):
        old_id = IdentityManager(tmp_path / "old").load_or_create_identity("peer")
        new_id = IdentityManager(tmp_path / "new").load_or_create_identity("peer")

        msg = build_key_migration_message(old_id, new_id)

        assert msg["type"] == "KEY_MIGRATION"
        assert msg["proto_ver"] == "1.0"
        assert msg["old_peer_id"] == old_id.peer_id
        assert msg["new_peer_id"] == new_id.peer_id
        assert "new_rsa_public_key_der_b64" in msg
        assert "old_key_signature_b64" in msg
        assert "new_key_signature_b64" in msg

    def test_verify_migration_with_valid_old_key(self, tmp_path):
        old_id = IdentityManager(tmp_path / "old").load_or_create_identity("peer")
        new_id = IdentityManager(tmp_path / "new").load_or_create_identity("peer")

        msg = build_key_migration_message(old_id, new_id)

        # Contact verifies using old public key they already trust
        new_peer_id, new_pub_b64 = verify_key_migration(msg, old_id.public_key)

        assert new_peer_id == new_id.peer_id
        assert new_pub_b64 == base64.b64encode(new_id.public_key_der).decode()

    def test_verify_migration_rejects_wrong_key(self, tmp_path):
        """Migration signed with wrong key must be rejected."""
        from cryptography.exceptions import InvalidSignature

        old_id = IdentityManager(tmp_path / "old").load_or_create_identity("peer")
        new_id = IdentityManager(tmp_path / "new").load_or_create_identity("peer")
        attacker_id = IdentityManager(tmp_path / "attacker").load_or_create_identity("attacker")

        msg = build_key_migration_message(old_id, new_id)

        # Verify using the WRONG (attacker's) public key — must fail
        with pytest.raises(Exception):
            verify_key_migration(msg, attacker_id.public_key)

    def test_verify_migration_rejects_tampered_message(self, tmp_path):
        """Tampered migration message must be rejected."""
        old_id = IdentityManager(tmp_path / "old").load_or_create_identity("peer")
        new_id = IdentityManager(tmp_path / "new").load_or_create_identity("peer")

        msg = build_key_migration_message(old_id, new_id)

        # Tamper: change the new_peer_id after signing
        msg["new_peer_id"] = "aaa" * 21  # Attacker trying to redirect to their key

        with pytest.raises(Exception):
            verify_key_migration(msg, old_id.public_key)

    def test_verify_migration_rejects_missing_fields(self, tmp_path):
        old_id = IdentityManager(tmp_path / "old").load_or_create_identity("peer")
        new_id = IdentityManager(tmp_path / "new").load_or_create_identity("peer")

        msg = build_key_migration_message(old_id, new_id)
        del msg["old_key_signature_b64"]

        with pytest.raises(ValueError):
            verify_key_migration(msg, old_id.public_key)

    def test_contact_is_updated_after_valid_migration(self, tmp_path):
        """After a valid migration, contacts store must be updated."""
        from storage.contacts_store import ContactsStore

        old_id = IdentityManager(tmp_path / "old").load_or_create_identity("alice")
        new_id = IdentityManager(tmp_path / "new").load_or_create_identity("alice")

        contacts_path = tmp_path / "contacts.json"
        contacts = ContactsStore(contacts_path)

        # Pre-populate with old contact
        data = {old_id.peer_id: {
            "peer_name": "alice",
            "rsa_public_key_der_b64": base64.b64encode(old_id.public_key_der).decode(),
        }}
        contacts.save(data)

        # Simulate receiving migration
        msg = build_key_migration_message(old_id, new_id)

        from cryptography.hazmat.primitives import serialization
        old_pub_der = base64.b64decode(data[old_id.peer_id]["rsa_public_key_der_b64"])
        old_pub_key = serialization.load_der_public_key(old_pub_der)

        new_peer_id, new_pub_b64 = verify_key_migration(msg, old_pub_key)

        # Update contacts
        current = contacts.load()
        current[new_peer_id] = {
            "peer_name": msg["new_peer_name"],
            "rsa_public_key_der_b64": new_pub_b64,
            "migrated_from": old_id.peer_id,
        }
        del current[old_id.peer_id]
        contacts.save(current)

        final = contacts.load()
        assert old_id.peer_id not in final          # Old entry removed
        assert new_id.peer_id in final              # New entry present
        assert final[new_id.peer_id]["peer_name"] == "alice"
        assert "migrated_from" in final[new_id.peer_id]

    def test_generate_new_identity_creates_different_keys(self, tmp_path):
        old_id = IdentityManager(tmp_path).load_or_create_identity("peer")
        new_id = generate_new_identity(tmp_path, "peer")
        assert old_id.peer_id != new_id.peer_id

    def test_generate_new_identity_replaces_stale_staged_keys(self, tmp_path):
        first_new = generate_new_identity(tmp_path, "peer")
        second_new = generate_new_identity(tmp_path, "peer")
        assert first_new.peer_id != second_new.peer_id

    def test_pending_migration_store_tracks_undelivered_contacts(self, tmp_path):
        store = PendingMigrationStore(tmp_path / "pending_migrations.json")
        notice_id = "old->new"
        message = {"type": "KEY_MIGRATION", "new_peer_id": "new"}

        store.queue_notice(notice_id, message, ["peer-a", "peer-b", "peer-a"])

        pending_a = store.get_pending_for_peer("peer-a")
        pending_b = store.get_pending_for_peer("peer-b")
        assert len(pending_a) == 1
        assert len(pending_b) == 1

        store.mark_delivered(notice_id, "peer-a")
        assert store.get_pending_for_peer("peer-a") == []
        assert len(store.get_pending_for_peer("peer-b")) == 1

        store.mark_delivered(notice_id, "peer-b")
        assert store.load()["notices"] == []
