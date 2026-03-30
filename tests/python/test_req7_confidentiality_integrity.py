"""
REQUIREMENT 7 — Confidentiality and Integrity of File Transfers
==============================================================
Tests that:
  - AES-256-GCM encrypts messages correctly (confidentiality)
  - Tampered ciphertext is detected (integrity)
  - Modified AAD is detected (replay / header tampering)
  - Per-message nonces mean identical plaintexts produce different ciphertext
  - SHA-256 hash detects file tampering in transit (FILE_TRANSFER_COMPLETE check)
  - Replay-attack protection: duplicate/out-of-order sequence numbers are rejected
"""
import hashlib
import os
import pytest
from cryptography.exceptions import InvalidTag

from crypto.session import SecureSession, encrypt, decrypt
from crypto.hashing import sha256_hex


# ── helpers ──────────────────────────────────────────────────────────────────

def make_session():
    """Create a matched pair of SecureSession objects (client ↔ server)."""
    send_key = os.urandom(32)
    recv_key = os.urandom(32)
    session_id = os.urandom(16).hex()
    client = SecureSession(session_id=session_id, send_key=send_key, recv_key=recv_key)
    server = SecureSession(session_id=session_id, send_key=recv_key, recv_key=send_key)
    return client, server


# ── AES-GCM confidentiality tests ────────────────────────────────────────────

class TestAesGcmConfidentiality:

    def test_encrypt_produces_ciphertext_different_from_plaintext(self):
        """Ciphertext must not contain plaintext bytes."""
        client, _ = make_session()
        plaintext = b"top secret file content"
        envelope = encrypt(client, "FILE_CHUNK", plaintext)
        ct = envelope["ciphertext_b64"]
        assert plaintext.decode() not in ct
        assert plaintext not in ct.encode()

    def test_two_encryptions_of_same_plaintext_differ(self):
        """Per-message random nonces ensure ciphertext is never reused."""
        client, _ = make_session()
        plaintext = b"same content every time"
        env1 = encrypt(client, "FILE_CHUNK", plaintext)
        env2 = encrypt(client, "FILE_CHUNK", plaintext)
        assert env1["nonce_b64"] != env2["nonce_b64"], "Nonces must be unique per message"
        assert env1["ciphertext_b64"] != env2["ciphertext_b64"], "Ciphertext must differ even for identical plaintext"

    def test_encrypt_then_decrypt_roundtrip(self):
        """Full encrypt→decrypt roundtrip must recover the original plaintext."""
        client, server = make_session()
        plaintext = b'{"type":"FILE_CHUNK","data":"deadbeef"}'
        envelope = encrypt(client, "FILE_CHUNK", plaintext)
        recovered = decrypt(server, envelope)
        assert recovered == plaintext


# ── AES-GCM integrity (authentication tag) tests ─────────────────────────────

class TestAesGcmIntegrity:

    def test_tampered_ciphertext_detected(self):
        """Flipping a bit in the ciphertext must raise InvalidTag."""
        import base64
        client, server = make_session()
        envelope = encrypt(client, "FILE_CHUNK", b"important payload")
        ct_bytes = base64.b64decode(envelope["ciphertext_b64"])
        ct_bytes = bytearray(ct_bytes)
        ct_bytes[0] ^= 0xFF                              # flip first byte
        envelope["ciphertext_b64"] = base64.b64encode(bytes(ct_bytes)).decode()
        with pytest.raises(Exception):
            decrypt(server, envelope)

    def test_tampered_aad_detected(self):
        """Replacing the AAD with a different value must raise InvalidTag."""
        import base64
        from protocol.canonical_json import canonical_json_bytes
        client, server = make_session()
        envelope = encrypt(client, "FILE_CHUNK", b"payload")
        # Build a bogus AAD (different seq number)
        bad_aad = canonical_json_bytes({
            "version": "1.0",
            "session_id": envelope["session_id"],
            "msg_seq": 999,
            "msg_type": "FILE_CHUNK",
        })
        envelope["aad_b64"] = base64.b64encode(bad_aad).decode()
        with pytest.raises(Exception):
            decrypt(server, envelope)

    def test_wrong_session_key_rejected(self):
        """Decrypting with a different recv_key must fail."""
        client, _ = make_session()
        _, wrong_server = make_session()   # different keys
        envelope = encrypt(client, "FILE_CHUNK", b"secret")
        with pytest.raises(Exception):
            decrypt(wrong_server, envelope)


# ── SHA-256 file-integrity tests ──────────────────────────────────────────────

class TestSha256FileIntegrity:

    def test_intact_file_passes_integrity_check(self):
        """SHA-256 of an unmodified file must match the sender's hash."""
        data = b"This is the original file content.\n" * 100
        sender_hash = sha256_hex(data)
        receiver_hash = hashlib.sha256(data).hexdigest()
        assert sender_hash == receiver_hash

    def test_tampered_file_detected(self):
        """A single-byte change must produce a completely different SHA-256."""
        original = b"Original file data " * 50
        tampered = bytearray(original)
        tampered[42] ^= 0x01
        assert sha256_hex(original) != sha256_hex(bytes(tampered)), \
            "SHA-256 must detect even a single-bit modification"

    def test_empty_file_has_known_sha256(self):
        """SHA-256 of empty bytes is a known constant — sanity check."""
        expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert sha256_hex(b"") == expected


# ── Sequence-number replay-protection tests ───────────────────────────────────

class TestReplayProtection:

    def test_replay_message_rejected(self):
        """A replayed message (same seq number) must be rejected."""
        client, server = make_session()
        envelope = encrypt(client, "PING", b'{"type":"PING"}')
        # First delivery succeeds
        decrypt(server, envelope)
        # Re-delivering the same envelope must fail
        with pytest.raises(ValueError, match="Replay"):
            decrypt(server, envelope)

    def test_out_of_order_message_rejected(self):
        """A message with seq ≤ already-seen seq must be rejected."""
        client, server = make_session()
        env1 = encrypt(client, "FILE_CHUNK", b"chunk 1")
        env2 = encrypt(client, "FILE_CHUNK", b"chunk 2")
        # Deliver msg2 first (seq=2), then try to deliver msg1 (seq=1)
        decrypt(server, env2)
        with pytest.raises(ValueError):
            decrypt(server, env1)
