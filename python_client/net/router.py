"""
Message router: dispatches incoming decrypted messages to handlers.

After the handshake establishes a SecureSession, all messages arrive as
AES-GCM encrypted envelopes. The router decrypts each one and calls the
appropriate handler based on the message type.
"""
import hashlib

from crypto.session import encrypt, decrypt
from net.file_receiver import FileReceiver
from net.framing import decode_frame, encode_frame, FramingError
from protocol.message_types import (
    LIST_FILES_REQUEST, LIST_FILES_RESPONSE,
    FILE_REQUEST, FILE_REQUEST_ACCEPT, FILE_REQUEST_DENY,
    FILE_CHUNK, FILE_TRANSFER_COMPLETE,
    KEY_MIGRATION,
    PING, PONG, ERROR,
)
from protocol.serializer import json_dumps_bytes, json_loads_bytes


class MessageRouter:
    """Routes decrypted protocol messages to the correct handler."""

    def __init__(self, ctx, conn, session, peer_name, peer_id):
        self.ctx = ctx
        self.conn = conn
        self.session = session
        self.peer_name = peer_name
        self.peer_id = peer_id
        self._receiver = FileReceiver()
        self._stream = conn.makefile("rb")

    def run(self):
        """Main loop: read encrypted frames, decrypt, dispatch."""
        while True:
            try:
                raw = decode_frame(self._stream)
            except FramingError:
                print(f"[NET] Connection closed: {self.peer_name}")
                break

            try:
                envelope = json_loads_bytes(raw)
                plaintext = decrypt(self.session, envelope)
                msg = json_loads_bytes(plaintext)
                self._dispatch(msg)
            except Exception as e:
                print(f"[ERROR] Message error from {self.peer_name}: {e}")
                self._send_error(str(e))

    # ------------------------------------------------------------------ #
    # Dispatch                                                             #
    # ------------------------------------------------------------------ #

    def _dispatch(self, msg: dict):
        t = msg.get("type")
        if t == LIST_FILES_REQUEST:
            self._on_list_files()
        elif t == FILE_REQUEST:
            self._on_file_request(msg)
        elif t == FILE_CHUNK:
            self._on_file_chunk(msg)
        elif t == FILE_TRANSFER_COMPLETE:
            self._on_transfer_complete(msg)
        elif t == KEY_MIGRATION:
            self._on_key_migration(msg)
        elif t == PING:
            self._send({PONG: PONG, "type": PONG})
        else:
            print(f"[NET] Unknown message type from {self.peer_name}: {t}")

    # ------------------------------------------------------------------ #
    # Handlers                                                             #
    # ------------------------------------------------------------------ #

    def _on_list_files(self):
        files = []
        if self.ctx and "share_manager" in self.ctx:
            files = self.ctx["share_manager"].list_files()
        self._send({"type": LIST_FILES_RESPONSE, "files": files})
        print(f"[INFO] Sent file list ({len(files)} files) to {self.peer_name}")

    def _on_file_request(self, msg: dict):
        filename = msg.get("file", "unknown")
        filesize = msg.get("filesize", 0)

        from net.consent_handler import prompt_receive_consent
        accepted = prompt_receive_consent(self.peer_name, filename, filesize)

        if accepted:
            self._send({"type": FILE_REQUEST_ACCEPT, "file": filename})
            print(f"[INFO] Accepted file '{filename}' from {self.peer_name}")
        else:
            self._send({"type": FILE_REQUEST_DENY, "file": filename,
                        "reason": "User declined"})
            print(f"[INFO] Declined file '{filename}' from {self.peer_name}")

    def _on_file_chunk(self, msg: dict):
        self._receiver.receive_chunk(msg)

    def _on_transfer_complete(self, msg: dict):
        filename = msg.get("file")
        expected_sha256 = msg.get("sha256_hex")

        data = self._receiver.assemble(filename)

        # Integrity check
        actual_sha256 = hashlib.sha256(data).hexdigest()
        if expected_sha256 and actual_sha256 != expected_sha256:
            print(f"[SECURITY ERROR] Integrity check FAILED for '{filename}'!")
            print(f"  Expected: {expected_sha256}")
            print(f"  Actual:   {actual_sha256}")
            print(f"  The file may have been tampered with in transit.")
            self._send_error(f"Integrity check failed for {filename}")
            return

        # Save to vault (encrypted at rest) or downloads folder
        if self.ctx and "vault_store" in self.ctx:
            self.ctx["vault_store"].store_file(filename, data)
            print(f"[INFO] '{filename}' saved to encrypted vault ({len(data):,} bytes)")
        else:
            from pathlib import Path
            dl = Path("downloads")
            dl.mkdir(exist_ok=True)
            (dl / filename).write_bytes(data)
            print(f"[INFO] '{filename}' saved to downloads/ ({len(data):,} bytes)")

        print(f"[INFO] Integrity OK: SHA-256={actual_sha256[:16]}...")

    def _on_key_migration(self, msg: dict):
        old_peer_id = msg.get("old_peer_id", "")

        if not (self.ctx and "contacts_store" in self.ctx):
            print(f"[WARNING] Key migration received but no contacts store available")
            return

        contacts = self.ctx["contacts_store"].load()
        old_contact = contacts.get(old_peer_id)

        if not old_contact:
            print(f"[SECURITY WARNING] Key migration from unknown peer: {old_peer_id[:16]}...")
            self._send_error("Key migration rejected: peer not in contacts")
            return

        try:
            import base64
            from cryptography.hazmat.primitives import serialization
            from crypto.key_migration import verify_key_migration

            old_pub_der = base64.b64decode(old_contact["rsa_public_key_der_b64"])
            old_pub_key = serialization.load_der_public_key(old_pub_der)
            new_peer_id, new_pub_b64 = verify_key_migration(msg, old_pub_key)

            # Update contacts
            contacts[new_peer_id] = {
                "peer_name": msg.get("new_peer_name"),
                "rsa_public_key_der_b64": new_pub_b64,
                "migrated_from": old_peer_id,
            }
            del contacts[old_peer_id]
            self.ctx["contacts_store"].save(contacts)

            print(f"[INFO] Key migration accepted: {msg.get('new_peer_name')} updated contact record")

        except Exception as e:
            print(f"[SECURITY ERROR] Key migration FAILED verification: {e}")
            print(f"  The migration message may be forged or corrupted.")
            self._send_error(f"Key migration verification failed: {e}")

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #

    def _send(self, msg: dict):
        msg_type = msg.get("type", "UNKNOWN")
        plaintext = json_dumps_bytes(msg)
        envelope = encrypt(self.session, msg_type, plaintext)
        payload = json_dumps_bytes(envelope)
        self.conn.sendall(encode_frame(payload))

    def _send_error(self, message: str):
        try:
            self._send({"type": ERROR, "message": message})
        except Exception:
            pass
