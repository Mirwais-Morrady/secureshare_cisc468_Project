import sys
from pathlib import Path
import pytest
import os

BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE_DIR))

from crypto.session import SecureSession, encrypt, decrypt


class TestSession:

    def _make_session(self):
        send_key = os.urandom(32)
        recv_key = os.urandom(32)
        session_id = "test-session-id-abc123"
        return SecureSession(session_id, send_key, recv_key)

    def _make_paired_sessions(self):
        """Create a pair of sessions where A's send == B's recv and vice versa."""
        key_a_to_b = os.urandom(32)
        key_b_to_a = os.urandom(32)
        session_id = "paired-session-id"
        session_a = SecureSession(session_id, key_a_to_b, key_b_to_a)
        session_b = SecureSession(session_id, key_b_to_a, key_a_to_b)
        return session_a, session_b

    def test_encrypt_returns_envelope_fields(self):
        session = self._make_session()
        plaintext = b'{"type": "PING"}'
        env = encrypt(session, "PING", plaintext)
        assert "version" in env
        assert "session_id" in env
        assert "msg_seq" in env
        assert "msg_type" in env
        assert "nonce_b64" in env
        assert "aad_b64" in env
        assert "ciphertext_b64" in env

    def test_encrypt_increments_sequence(self):
        session = self._make_session()
        env1 = encrypt(session, "PING", b"data1")
        env2 = encrypt(session, "PING", b"data2")
        assert env1["msg_seq"] == 1
        assert env2["msg_seq"] == 2

    def test_encrypt_decrypt_roundtrip(self):
        session_a, session_b = self._make_paired_sessions()
        plaintext = b'{"type": "PING", "data": "hello"}'
        env = encrypt(session_a, "PING", plaintext)
        result = decrypt(session_b, env)
        assert result == plaintext

    def test_decrypt_multiple_messages(self):
        session_a, session_b = self._make_paired_sessions()
        messages = [b"msg1", b"msg2", b"msg3"]
        for msg in messages:
            env = encrypt(session_a, "DATA", msg)
            result = decrypt(session_b, env)
            assert result == msg

    def test_nonce_is_different_each_time(self):
        session = self._make_session()
        env1 = encrypt(session, "PING", b"data")
        env2 = encrypt(session, "PING", b"data")
        assert env1["nonce_b64"] != env2["nonce_b64"]

    def test_session_id_in_envelope(self):
        session = self._make_session()
        env = encrypt(session, "PING", b"data")
        assert env["session_id"] == session.session_id

    def test_decrypt_fails_with_wrong_key(self):
        session_a, _ = self._make_paired_sessions()
        bad_session = SecureSession("paired-session-id", os.urandom(32), os.urandom(32))
        env = encrypt(session_a, "PING", b"data")
        with pytest.raises(Exception):
            decrypt(bad_session, env)
