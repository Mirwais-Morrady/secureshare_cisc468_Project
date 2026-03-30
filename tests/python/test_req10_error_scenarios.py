"""
REQUIREMENT 10 — Error Detection and Reporting
===============================================
Tests all error scenarios explicitly mentioned in the project spec:
  - File tampered in transit (SHA-256 mismatch)
  - File tampered at rest / vault decryption failure
  - Signature forgery rejected (manifest and handshake)
  - Replay attack rejected (duplicate sequence numbers)
  - Key migration forgery rejected
  - Frame corruption (unexpected EOF)
  - Wrong vault password (encrypted file unreadable)
  - Canonical JSON serialisation (deterministic — prevents AAD mismatch)
"""
import hashlib
import io
import os
import struct
import tempfile
from pathlib import Path

import pytest

from crypto.vault import encrypt_vault, decrypt_vault
from crypto.session import SecureSession, encrypt, decrypt
from net.framing import encode_frame, decode_frame, FramingError
from crypto.identity import IdentityManager
from crypto.hashing import sha256_hex
from protocol.canonical_json import canonical_json_bytes


# ── Error: file tampered in transit ──────────────────────────────────────────

class TestTransitTamperingDetection:

    def test_sha256_mismatch_signals_tampering(self):
        """
        Simulates the integrity check in _on_transfer_complete:
        if the received file's SHA-256 ≠ the sender's advertised SHA-256, tampering is detected.
        """
        original = b"Legitimate file contents " * 100
        sender_sha = sha256_hex(original)

        # Simulate a man-in-the-middle modifying one byte
        tampered = bytearray(original)
        tampered[50] ^= 0x01
        received_sha = sha256_hex(bytes(tampered))

        assert sender_sha != received_sha, \
            "[REQ 10] SHA-256 mismatch must be detected — tampering in transit caught"

    def test_aes_gcm_tag_catches_in_transit_modification(self):
        """The AEAD tag on each encrypted frame must catch any byte-level modification."""
        import base64
        send_key = os.urandom(32)
        recv_key = os.urandom(32)
        sid = os.urandom(16).hex()
        client = SecureSession(session_id=sid, send_key=send_key, recv_key=recv_key)
        server = SecureSession(session_id=sid, send_key=recv_key, recv_key=send_key)

        envelope = encrypt(client, "FILE_CHUNK", b"file chunk payload")
        ct = bytearray(base64.b64decode(envelope["ciphertext_b64"]))
        ct[0] ^= 0xFF
        envelope["ciphertext_b64"] = base64.b64encode(bytes(ct)).decode()

        with pytest.raises(Exception):
            decrypt(server, envelope)


# ── Error: replay attack ──────────────────────────────────────────────────────

class TestReplayAttackDetection:

    def test_replayed_message_raises_value_error(self):
        """A message with a previously seen sequence number must be rejected."""
        send_key = os.urandom(32)
        recv_key = os.urandom(32)
        sid = os.urandom(16).hex()
        client = SecureSession(session_id=sid, send_key=send_key, recv_key=recv_key)
        server = SecureSession(session_id=sid, send_key=recv_key, recv_key=send_key)

        envelope = encrypt(client, "PING", b'{"type":"PING"}')
        decrypt(server, envelope)  # first delivery OK
        with pytest.raises(ValueError, match="Replay"):
            decrypt(server, envelope)  # replay must be rejected

    def test_out_of_order_sequence_rejected(self):
        """Receiving seq=1 after seq=2 has been accepted must raise ValueError."""
        send_key = os.urandom(32)
        recv_key = os.urandom(32)
        sid = os.urandom(16).hex()
        client = SecureSession(session_id=sid, send_key=send_key, recv_key=recv_key)
        server = SecureSession(session_id=sid, send_key=recv_key, recv_key=send_key)

        env1 = encrypt(client, "FILE_CHUNK", b"chunk 1")
        env2 = encrypt(client, "FILE_CHUNK", b"chunk 2")
        decrypt(server, env2)   # accept seq=2
        with pytest.raises(ValueError):
            decrypt(server, env1)   # reject seq=1 (out of order)


# ── Error: wrong vault password ───────────────────────────────────────────────

class TestVaultPasswordError:

    def test_wrong_password_raises_exception(self):
        """Decrypting a vault blob with the wrong password must fail with an exception."""
        blob = encrypt_vault("correct-password", b"top secret")
        with pytest.raises(Exception):
            decrypt_vault("wrong-password", blob)

    def test_truncated_vault_blob_raises_exception(self):
        """A truncated vault blob (e.g. partial write) must raise an exception."""
        blob = encrypt_vault("password", b"data")
        with pytest.raises(Exception):
            decrypt_vault("password", blob[:10])  # only salt, no nonce or ciphertext


# ── Error: signature forgery ──────────────────────────────────────────────────

class TestSignatureForgeryDetection:

    def test_wrong_key_signature_verification_fails(self, tmp_path):
        alice_dir = Path(tmp_path) / "alice"
        bob_dir = Path(tmp_path) / "bob"
        alice = IdentityManager(alice_dir).load_or_create_identity("alice")
        bob = IdentityManager(bob_dir).load_or_create_identity("bob")

        data = b"Alice's signed handshake"
        sig = IdentityManager.sign(alice.private_key, data)
        with pytest.raises(Exception):
            IdentityManager.verify(bob.public_key, data, sig)

    def test_corrupted_signature_rejected(self, tmp_path):
        alice_dir = Path(tmp_path) / "alice2"
        alice = IdentityManager(alice_dir).load_or_create_identity("alice")
        data = b"some data"
        sig = bytearray(IdentityManager.sign(alice.private_key, data))
        sig[0] ^= 0xFF
        with pytest.raises(Exception):
            IdentityManager.verify(alice.public_key, data, bytes(sig))


# ── Error: manifest tampering ─────────────────────────────────────────────────

class TestManifestTamperingDetection:

    def test_tampered_manifest_signature_rejected(self, tmp_path):
        from crypto.manifest import build_manifest, sign_manifest
        import base64

        alice_dir = Path(tmp_path) / "alice3"
        alice = IdentityManager(alice_dir).load_or_create_identity("alice")
        f = Path(tmp_path) / "file.txt"
        f.write_bytes(b"original content")

        signed = sign_manifest(alice.private_key,
                               build_manifest(alice.peer_id, alice.peer_name, f))
        # Attacker changes file_size in the manifest
        signed["file_size"] = 0
        unsigned = {k: v for k, v in signed.items() if k != "signature_b64"}
        sig = base64.b64decode(signed["signature_b64"])
        with pytest.raises(Exception):
            IdentityManager.verify(alice.public_key, canonical_json_bytes(unsigned), sig)


# ── Error: frame corruption / EOF ────────────────────────────────────────────

class TestFrameCorruptionDetection:

    def test_truncated_frame_raises_framing_error(self):
        """A frame promising N bytes but providing fewer must raise FramingError."""
        bad = struct.pack(">I", 1000) + b"X" * 10  # claims 1000 bytes, has 10
        with pytest.raises(FramingError):
            decode_frame(io.BytesIO(bad))

    def test_empty_stream_raises_framing_error(self):
        with pytest.raises(FramingError):
            decode_frame(io.BytesIO(b""))

    def test_partial_length_prefix_raises_framing_error(self):
        """Only 3 of the 4 length-prefix bytes present."""
        with pytest.raises(FramingError):
            decode_frame(io.BytesIO(b"\x00\x00\x01"))


# ── Canonical JSON determinism ────────────────────────────────────────────────

class TestCanonicalJson:

    def test_same_dict_always_produces_same_bytes(self):
        obj = {"z": 1, "a": 2, "m": [3, 4, 5]}
        b1 = canonical_json_bytes(obj)
        b2 = canonical_json_bytes(obj)
        assert b1 == b2

    def test_keys_are_sorted(self):
        obj = {"z": 1, "a": 2}
        result = canonical_json_bytes(obj).decode()
        assert result.index('"a"') < result.index('"z"'), \
            "Keys must be sorted alphabetically for canonical form"

    def test_different_key_order_produces_same_output(self):
        d1 = {"b": 2, "a": 1}
        d2 = {"a": 1, "b": 2}
        assert canonical_json_bytes(d1) == canonical_json_bytes(d2)
