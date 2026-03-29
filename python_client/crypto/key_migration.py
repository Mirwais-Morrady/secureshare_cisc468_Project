"""
Key migration protocol.

Allows a peer to notify contacts that their RSA identity key has been
compromised and has been replaced with a new one.

The migration message is signed with BOTH the old key (proving the message
comes from the legitimate old identity) and the new key (proving ownership
of the new key). Contacts verify using the old key they already trust.
"""

import base64
from pathlib import Path

from crypto.identity import IdentityManager
from crypto.identity import PRIVATE_KEY_FILE, PUBLIC_KEY_FILE
from protocol.canonical_json import canonical_json_bytes
from crypto.session import encrypt
from net.framing import encode_frame
from protocol.serializer import json_dumps_bytes
from protocol.message_types import KEY_MIGRATION


def build_key_migration_message(old_identity, new_identity):
    """
    Build a KEY_MIGRATION message.

    Signed with the OLD private key so contacts can verify using the
    old public key they already have on file.
    Also signed with the NEW private key to prove ownership.

    Args:
        old_identity: The compromised/old Identity object
        new_identity: The new Identity object

    Returns:
        dict: The signed KEY_MIGRATION message
    """
    # Build unsigned body
    msg = {
        "type": "KEY_MIGRATION",
        "proto_ver": "1.0",
        "old_peer_id": old_identity.peer_id,
        "new_peer_id": new_identity.peer_id,
        "new_peer_name": new_identity.peer_name,
        "new_rsa_public_key_der_b64": base64.b64encode(new_identity.public_key_der).decode(),
    }

    # Sign with old key (contacts can verify this)
    old_sig = IdentityManager.sign(old_identity.private_key, canonical_json_bytes(msg))
    msg["old_key_signature_b64"] = base64.b64encode(old_sig).decode()

    # Sign with new key (proves ownership of new key)
    body_for_new_sig = {k: v for k, v in msg.items() if k != "old_key_signature_b64"}
    new_sig = IdentityManager.sign(new_identity.private_key, canonical_json_bytes(body_for_new_sig))
    msg["new_key_signature_b64"] = base64.b64encode(new_sig).decode()

    return msg


def verify_key_migration(migration_msg, old_public_key):
    """
    Verify a KEY_MIGRATION message using the previously trusted old public key.

    Args:
        migration_msg: The KEY_MIGRATION message dict
        old_public_key: The RSA public key object we already trust for this peer

    Returns:
        tuple: (new_peer_id, new_rsa_public_key_der_b64) if valid

    Raises:
        ValueError: If required fields are missing
        cryptography.exceptions.InvalidSignature: If signature is invalid
    """
    required = ["type", "proto_ver", "old_peer_id", "new_peer_id",
                "new_peer_name", "new_rsa_public_key_der_b64",
                "old_key_signature_b64", "new_key_signature_b64"]
    for field in required:
        if field not in migration_msg:
            raise ValueError(f"KEY_MIGRATION missing required field: {field}")

    if migration_msg["type"] != "KEY_MIGRATION":
        raise ValueError("Message is not KEY_MIGRATION")

    # Verify old-key signature (covers everything except the two signature fields)
    body = {k: v for k, v in migration_msg.items()
            if k not in ("old_key_signature_b64", "new_key_signature_b64")}
    old_sig = base64.b64decode(migration_msg["old_key_signature_b64"])
    IdentityManager.verify(old_public_key, canonical_json_bytes(body), old_sig)

    return migration_msg["new_peer_id"], migration_msg["new_rsa_public_key_der_b64"]


def generate_new_identity(identity_dir, peer_name):
    """
    Generate a fresh RSA identity (new key pair) for migration.

    The new keys are saved alongside the old ones with a '_new' suffix
    until the migration is confirmed.

    Args:
        identity_dir: Path to the identity directory
        peer_name: The peer name to use for the new identity

    Returns:
        Identity: The new identity object (not yet saved as primary)
    """
    new_dir = Path(identity_dir) / "new"
    new_dir.mkdir(parents=True, exist_ok=True)

    # A new rotation must produce a fresh key pair even if a previous
    # staged identity already exists in data/identity/new/.
    for key_file in (PRIVATE_KEY_FILE, PUBLIC_KEY_FILE):
        staged = new_dir / key_file
        if staged.exists():
            staged.unlink()

    mgr = IdentityManager(new_dir)
    return mgr.load_or_create_identity(peer_name)


def send_key_migration(sock, session, migration_msg):
    plaintext = json_dumps_bytes(migration_msg)
    envelope = encrypt(session, KEY_MIGRATION, plaintext)
    sock.sendall(encode_frame(json_dumps_bytes(envelope)))


def flush_pending_migrations(ctx, peer_id: str, sock, session, peer_name: str = "unknown"):
    store = ctx.get("pending_migration_store") if ctx else None
    if store is None:
        return 0

    sent = 0
    for notice in store.get_pending_for_peer(peer_id):
        send_key_migration(sock, session, notice["message"])
        store.mark_delivered(notice["id"], peer_id)
        sent += 1
        print(f"[ROTATE-KEY] Delivered pending KEY_MIGRATION to '{peer_name}'")

    return sent