"""
Tests for security failure scenarios and error message display (Requirements 2, 7, 10).

Covers:
- Authentication failure (bad signature on handshake message)
- Replay attack prevention (sequence number checks)
- Tamper detection in transit (wrong key / corrupted ciphertext)
- Vault access with wrong password
- Mutual authentication: each side verifies the other
"""
import sys
from pathlib import Path
import pytest
import os
import base64

BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE_DIR))

from crypto.identity import IdentityManager
from crypto.session import SecureSession, encrypt, decrypt


class TestAuthenticationFailure:

    def test_tampered_client_hello_signature_rejected(self, tmp_path):
        """A CLIENT_HELLO with a modified field after signing must fail verification."""
        from cryptography.exceptions import InvalidSignature
        from net.handshake_client import build_client_hello
        from protocol.serializer import json_dumps_bytes

        identity = IdentityManager(tmp_path).load_or_create_identity("peer")
        hello, _, _ = build_client_hello(identity)

        # Tamper: change peer_name after signing
        hello["peer_name"] = "ATTACKER"

        # Attempt to verify
        unsigned = {k: v for k, v in hello.items() if k != "signature_b64"}
        sig = base64.b64decode(hello["signature_b64"])
        with pytest.raises(Exception):
            IdentityManager.verify(identity.public_key, json_dumps_bytes(unsigned), sig)

    def test_cross_peer_signature_rejected(self, tmp_path):
        """A signature from peer A cannot be verified with peer B's public key."""
        from net.handshake_client import build_client_hello
        from protocol.serializer import json_dumps_bytes

        peer_a = IdentityManager(tmp_path / "a").load_or_create_identity("A")
        peer_b = IdentityManager(tmp_path / "b").load_or_create_identity("B")

        hello, _, _ = build_client_hello(peer_a)
        unsigned = {k: v for k, v in hello.items() if k != "signature_b64"}
        sig = base64.b64decode(hello["signature_b64"])

        with pytest.raises(Exception):
            IdentityManager.verify(peer_b.public_key, json_dumps_bytes(unsigned), sig)

    def test_mutual_authentication_both_sides_verify(self, tmp_path):
        """Both client and server must verify each other's signatures."""
        import socket, threading
        from net.handshake_client import execute_client_handshake
        from net.handshake_server import execute_server_handshake

        port = _free_port()
        client_id = IdentityManager(tmp_path / "c").load_or_create_identity("client")
        server_id = IdentityManager(tmp_path / "s").load_or_create_identity("server")
        errors = []
        server_session_ref = [None]

        def run_server():
            srv = socket.socket()
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", port))
            srv.listen(1)
            conn, _ = srv.accept()
            try:
                session, _ = execute_server_handshake(conn, server_id)
                server_session_ref[0] = session
            except Exception as e:
                errors.append(e)
            finally:
                srv.close()

        t = threading.Thread(target=run_server)
        t.start()
        import time; time.sleep(0.05)

        client_sock = socket.socket()
        client_sock.connect(("127.0.0.1", port))
        try:
            client_session, server_hello = execute_client_handshake(client_sock, client_id)
        except Exception as e:
            errors.append(e)
        finally:
            client_sock.close()
        t.join(timeout=3)

        assert not errors, f"Authentication errors: {errors}"
        assert server_session_ref[0] is not None
        # Both sides derived the same session
        assert client_session.session_id == server_session_ref[0].session_id


class TestReplayAttack:

    def test_replay_message_is_rejected(self):
        """A replayed message (same seq number) must be rejected by decrypt."""
        key = os.urandom(32)
        session = SecureSession("sid", key, key, send_seq=0, recv_seq=0)

        # Encrypt message seq=1
        env = encrypt(session, "PING", b"data")
        # Reset recv_seq so we can decrypt once
        session.recv_seq = 0
        decrypt(session, env)

        # Attempt replay: recv_seq is now 1, replaying env (seq=1) should fail
        with pytest.raises(Exception):
            decrypt(session, env)

    def test_out_of_order_rejected(self):
        """A message with seq <= recv_seq must be rejected."""
        key = os.urandom(32)
        send_session = SecureSession("sid", key, key, send_seq=5, recv_seq=0)
        recv_session = SecureSession("sid", key, key, send_seq=0, recv_seq=10)

        env = encrypt(send_session, "PING", b"data")  # seq=6
        # recv_seq=10 > seq=6, must reject
        with pytest.raises(Exception):
            decrypt(recv_session, env)


class TestIntegrityFailure:

    def test_tampered_ciphertext_is_detected(self):
        """AES-GCM authentication tag detects any ciphertext modification."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import struct

        key = os.urandom(32)
        nonce = os.urandom(12)
        aad = b"header"
        plaintext = b"secret file data"

        aes = AESGCM(key)
        ciphertext = aes.encrypt(nonce, plaintext, aad)

        # Flip one bit in the ciphertext
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF
        tampered = bytes(tampered)

        with pytest.raises(Exception):
            aes.decrypt(nonce, tampered, aad)

    def test_wrong_aad_is_detected(self):
        """AES-GCM authentication tag detects AAD modification."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        key = os.urandom(32)
        nonce = os.urandom(12)
        aad = b'{"session_id":"abc","msg_seq":1}'
        plaintext = b"message"

        aes = AESGCM(key)
        ciphertext = aes.encrypt(nonce, plaintext, aad)

        wrong_aad = b'{"session_id":"abc","msg_seq":2}'  # Different seq
        with pytest.raises(Exception):
            aes.decrypt(nonce, ciphertext, wrong_aad)


class TestVaultSecurity:

    def test_vault_wrong_password_fails(self):
        from crypto.vault import encrypt_vault, decrypt_vault
        encrypted = encrypt_vault("correct-password", b"secret data")
        with pytest.raises(Exception):
            decrypt_vault("wrong-password", encrypted)

    def test_vault_store_wrong_password_fails(self, tmp_path):
        from storage.vault_store import VaultStore
        vault = VaultStore(tmp_path / "vault", password="correct")
        vault.store_file("test.txt", b"secret")

        wrong_vault = VaultStore(tmp_path / "vault", password="wrong")
        with pytest.raises(Exception):
            wrong_vault.get_file("test.txt")

    def test_vault_file_unreadable_without_password(self, tmp_path):
        """Encrypted vault files are not human-readable."""
        from storage.vault_store import VaultStore
        vault = VaultStore(tmp_path / "vault", password="password")
        vault.store_file("secret.txt", b"my secret content")

        # Read raw bytes from the .enc file
        enc_file = tmp_path / "vault" / "secret.txt.enc"
        raw = enc_file.read_bytes()

        # Raw bytes must not contain the plaintext
        assert b"my secret content" not in raw


def _free_port():
    import socket as s
    with s.socket() as sock:
        sock.bind(("", 0))
        return sock.getsockname()[1]
