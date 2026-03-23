import sys
from pathlib import Path
import pytest
import base64

BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE_DIR))

from crypto.identity import IdentityManager
from protocol.handshake import (
    generate_dh_keypair,
    compute_shared_secret,
    derive_session_keys,
    transcript_hash,
)
from protocol.canonical_json import canonical_json_bytes
from crypto.hashing import sha256_bytes


class TestHandshakeCrypto:

    def test_dh_keypair_generation(self):
        priv, pub = generate_dh_keypair()
        assert isinstance(priv, int)
        assert isinstance(pub, int)
        assert priv > 0
        assert pub > 1  # Must be at least 2

    def test_dh_shared_secret_is_symmetric(self):
        priv_a, pub_a = generate_dh_keypair()
        priv_b, pub_b = generate_dh_keypair()
        shared_ab = compute_shared_secret(priv_a, pub_b)
        shared_ba = compute_shared_secret(priv_b, pub_a)
        assert shared_ab == shared_ba

    def test_shared_secret_is_bytes(self):
        priv, pub = generate_dh_keypair()
        shared = compute_shared_secret(priv, pub)
        assert isinstance(shared, bytes)
        assert len(shared) > 0  # Non-empty shared secret

    def test_derive_session_keys_returns_three_values(self):
        shared = b"x" * 32
        transcript = b"y" * 32
        send_key, recv_key, session_id = derive_session_keys(shared, transcript)
        assert len(send_key) == 32
        assert len(recv_key) == 32
        assert isinstance(session_id, str)
        assert len(session_id) == 32  # 16 bytes hex = 32 chars

    def test_session_keys_differ(self):
        shared = b"x" * 32
        transcript = b"y" * 32
        send_key, recv_key, session_id = derive_session_keys(shared, transcript)
        assert send_key != recv_key

    def test_transcript_hash_is_deterministic(self):
        client_hello = {"type": "CLIENT_HELLO", "proto_ver": "1.0", "peer_name": "python-peer"}
        server_hello = {"type": "SERVER_HELLO", "proto_ver": "1.0", "peer_name": "java-peer"}
        h1 = transcript_hash(client_hello, server_hello)
        h2 = transcript_hash(client_hello, server_hello)
        assert h1 == h2

    def test_transcript_hash_equals_sha256_of_canonical_concat(self):
        client_hello = {"type": "CLIENT_HELLO", "proto_ver": "1.0"}
        server_hello = {"type": "SERVER_HELLO", "proto_ver": "1.0"}
        expected = sha256_bytes(
            canonical_json_bytes(client_hello) + canonical_json_bytes(server_hello)
        )
        result = transcript_hash(client_hello, server_hello)
        assert result == expected

    def test_transcript_hash_changes_with_different_messages(self):
        client_hello = {"type": "CLIENT_HELLO", "nonce": "aaa"}
        server_hello = {"type": "SERVER_HELLO", "nonce": "bbb"}
        server_hello2 = {"type": "SERVER_HELLO", "nonce": "ccc"}
        h1 = transcript_hash(client_hello, server_hello)
        h2 = transcript_hash(client_hello, server_hello2)
        assert h1 != h2

    def test_build_client_hello_contains_required_fields(self, tmp_path):
        from net.handshake_client import build_client_hello
        mgr = IdentityManager(tmp_path)
        identity = mgr.load_or_create_identity("test-peer")
        hello, priv, pub = build_client_hello(identity)
        assert hello["type"] == "CLIENT_HELLO"
        assert hello["proto_ver"] == "1.0"
        assert "peer_name" in hello
        assert "peer_id" in hello
        assert "rsa_public_key_der_b64" in hello
        assert "dh_public_b64" in hello
        assert "nonce1_b64" in hello
        assert "signature_b64" in hello
        assert isinstance(priv, int)
        assert isinstance(pub, int)

    def test_build_server_hello_contains_required_fields(self, tmp_path):
        from net.handshake_server import build_server_hello
        mgr = IdentityManager(tmp_path)
        identity = mgr.load_or_create_identity("test-peer")
        client_nonce = base64.b64encode(b"x" * 16).decode()
        hello, priv, pub = build_server_hello(identity, client_nonce)
        assert hello["type"] == "SERVER_HELLO"
        assert hello["proto_ver"] == "1.0"
        assert "peer_name" in hello
        assert "peer_id" in hello
        assert "rsa_public_key_der_b64" in hello
        assert "dh_public_b64" in hello
        assert "nonce2_b64" in hello
        assert "client_nonce1_b64" in hello
        assert "signature_b64" in hello

    def test_full_session_derivation(self, tmp_path):
        """Test that two peers can derive the same session keys."""
        from net.handshake_client import build_client_hello
        from net.handshake_server import build_server_hello
        from crypto.dh_params import bytes_to_int

        client_id_dir = tmp_path / "client_identity"
        server_id_dir = tmp_path / "server_identity"

        client_mgr = IdentityManager(client_id_dir)
        server_mgr = IdentityManager(server_id_dir)

        client_identity = client_mgr.load_or_create_identity("client")
        server_identity = server_mgr.load_or_create_identity("server")

        # Client builds CLIENT_HELLO
        client_hello, client_dh_priv, client_dh_pub = build_client_hello(client_identity)

        # Server builds SERVER_HELLO
        server_hello, server_dh_priv, server_dh_pub = build_server_hello(
            server_identity, client_hello["nonce1_b64"]
        )

        # Client derives session keys
        server_dh_pub_int = bytes_to_int(base64.b64decode(server_hello["dh_public_b64"]))
        client_shared = compute_shared_secret(client_dh_priv, server_dh_pub_int)
        thash = transcript_hash(client_hello, server_hello)
        client_send, client_recv, client_sid = derive_session_keys(client_shared, thash)

        # Server derives session keys (same function returns client_to_server, server_to_client)
        client_dh_pub_int = bytes_to_int(base64.b64decode(client_hello["dh_public_b64"]))
        server_shared = compute_shared_secret(server_dh_priv, client_dh_pub_int)
        # derive_session_keys always returns (c2s, s2c, session_id)
        s_c2s_key, s_s2c_key, server_sid = derive_session_keys(server_shared, thash)

        # Both sides must derive the same shared secret, so the keys are symmetric
        assert client_sid == server_sid
        # client_send (c2s) == server's c2s key
        assert client_send == s_c2s_key
        # client_recv (s2c) == server's s2c key
        assert client_recv == s_s2c_key
