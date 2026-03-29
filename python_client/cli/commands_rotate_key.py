import shutil
from pathlib import Path

from crypto.identity import IdentityManager
from crypto.key_migration import build_key_migration_message, generate_new_identity
from crypto.session import encrypt
from net.framing import encode_frame
from protocol.message_types import KEY_MIGRATION
from protocol.serializer import json_dumps_bytes


def _send_migration(sock, session, msg):
    plaintext = json_dumps_bytes(msg)
    envelope  = encrypt(session, KEY_MIGRATION, plaintext)
    sock.sendall(encode_frame(json_dumps_bytes(envelope)))


def rotate_key(ctx, cmd):
    """
    rotate-key

    Generates a fresh RSA-2048 key pair, builds a KEY_MIGRATION message
    signed with both the old and new private keys, broadcasts it to all
    currently connected peers, then replaces the on-disk identity with
    the new keys and updates the in-process identity.

    Contacts who receive the message verify it using the old key they
    already trust, then update their contact record to the new public key.
    This satisfies Requirement 6 (key migration / compromise recovery).
    """
    old_identity = ctx["identity"]
    base_dir = Path(__file__).resolve().parent.parent

    print("[ROTATE-KEY] Generating new RSA-2048 key pair ...")
    new_identity = generate_new_identity(base_dir / "data" / "identity",
                                         old_identity.peer_name)
    print(f"[ROTATE-KEY] New peer ID : {new_identity.peer_id[:32]}...")

    # Build the migration message signed with both keys
    migration_msg = build_key_migration_message(old_identity, new_identity)
    print(f"[ROTATE-KEY] Migration message built and signed with both keys.")

    # Broadcast to all active connections
    connections = ctx.get("connections", {})
    if not connections:
        print("[ROTATE-KEY] No active connections — migration message not broadcast.")
        print("             (Connect to peers before rotating if you want them notified)")
    else:
        notified = []
        failed   = []
        for peer_name, conn in list(connections.items()):
            try:
                _send_migration(conn["sock"], conn["session"], migration_msg)
                notified.append(peer_name)
                print(f"[ROTATE-KEY] Sent KEY_MIGRATION to '{peer_name}'")
            except Exception as e:
                failed.append(peer_name)
                print(f"[WARN] Could not notify '{peer_name}': {e}")

        if notified:
            print(f"[ROTATE-KEY] Notified {len(notified)} peer(s): {', '.join(notified)}")
        if failed:
            print(f"[WARN] Failed to notify: {', '.join(failed)}")

    # Promote new keys to primary identity directory
    identity_dir = base_dir / "data" / "identity"
    new_dir      = identity_dir / "new"

    # Back up old keys
    old_dir = identity_dir / "old"
    old_dir.mkdir(parents=True, exist_ok=True)
    for fname in ("private_key.pem", "public_key.pem"):
        src = identity_dir / fname
        if src.exists():
            shutil.copy2(src, old_dir / fname)

    # Overwrite primary keys with new keys
    for fname in ("private_key.pem", "public_key.pem"):
        src = new_dir / fname
        if src.exists():
            shutil.copy2(src, identity_dir / fname)

    # Update in-process identity
    ctx["identity"] = new_identity

    # Drop all existing connections — they used the old session keys
    for peer_name, conn in list(connections.items()):
        try:
            conn["sock"].close()
        except Exception:
            pass
    ctx["connections"] = {}

    print()
    print(f"[OK] Key rotation complete.")
    print(f"  Old peer ID : {old_identity.peer_id[:32]}...")
    print(f"  New peer ID : {new_identity.peer_id[:32]}...")
    print(f"  Old keys backed up to : data/identity/old/")
    print(f"  New keys now active.")
    print()
    print(f"[INFO] All existing connections have been closed.")
    print(f"       Reconnect to peers — they will see your new identity.")
    print(f"       Peers who received the KEY_MIGRATION message have already")
    print(f"       updated their contact record to trust your new public key.")
