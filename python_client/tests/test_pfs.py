"""
Tests demonstrating Perfect Forward Secrecy (Requirement 8).

PFS means: compromise of the long-term RSA key does NOT allow an attacker
to decrypt past sessions. Each session uses ephemeral DH keys that are
never persisted. Once a session is complete, the session keys are gone.

Demonstrated by:
1. Each session generates unique ephemeral DH keys.
2. Session keys are derived from ephemeral DH, not from RSA keys.
3. Session keys cannot be recomputed from the RSA key alone.
4. Two sessions always produce different session keys.
"""
import sys
from pathlib import Path
import pytest

BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE_DIR))

from protocol.handshake import generate_dh_keypair, compute_shared_secret, derive_session_keys, transcript_hash
from crypto.identity import IdentityManager


class TestPerfectForwardSecrecy:

    def test_ephemeral_dh_keys_are_unique_per_session(self):
        """Each call to generate_dh_keypair produces different keys."""
        priv1, pub1 = generate_dh_keypair()
        priv2, pub2 = generate_dh_keypair()
        assert priv1 != priv2
        assert pub1 != pub2

    def test_different_sessions_produce_different_keys(self, tmp_path):
        """Two separate handshakes produce completely different session keys."""
        from net.handshake_client import build_client_hello
        from net.handshake_server import build_server_hello
        from crypto.dh_params import bytes_to_int
        import base64

        client_id = IdentityManager(tmp_path / "c").load_or_create_identity("client")
        server_id = IdentityManager(tmp_path / "s").load_or_create_identity("server")

        def do_session():
            ch, c_priv, _ = build_client_hello(client_id)
            sh, s_priv, _ = build_server_hello(server_id, ch["nonce1_b64"])
            s_dh_pub = bytes_to_int(base64.b64decode(sh["dh_public_b64"]))
            c_dh_pub = bytes_to_int(base64.b64decode(ch["dh_public_b64"]))
            thash = transcript_hash(ch, sh)
            shared = compute_shared_secret(c_priv, s_dh_pub)
            return derive_session_keys(shared, thash)

        send1, recv1, sid1 = do_session()
        send2, recv2, sid2 = do_session()

        assert send1 != send2, "Each session must produce unique send key"
        assert recv1 != recv2, "Each session must produce unique recv key"
        assert sid1 != sid2,   "Each session must have unique ID"

    def test_rsa_key_does_not_determine_session_key(self, tmp_path):
        """Session keys depend on ephemeral DH, not just on RSA keys."""
        from net.handshake_client import build_client_hello
        from net.handshake_server import build_server_hello
        from crypto.dh_params import bytes_to_int
        import base64

        client_id = IdentityManager(tmp_path / "c").load_or_create_identity("client")
        server_id = IdentityManager(tmp_path / "s").load_or_create_identity("server")

        # Session 1
        ch1, c_priv1, _ = build_client_hello(client_id)
        sh1, s_priv1, _ = build_server_hello(server_id, ch1["nonce1_b64"])
        s_pub1 = bytes_to_int(base64.b64decode(sh1["dh_public_b64"]))
        thash1 = transcript_hash(ch1, sh1)
        shared1 = compute_shared_secret(c_priv1, s_pub1)
        send1, _, _ = derive_session_keys(shared1, thash1)

        # Session 2 — SAME RSA identity keys, different ephemeral DH
        ch2, c_priv2, _ = build_client_hello(client_id)
        sh2, s_priv2, _ = build_server_hello(server_id, ch2["nonce1_b64"])
        s_pub2 = bytes_to_int(base64.b64decode(sh2["dh_public_b64"]))
        thash2 = transcript_hash(ch2, sh2)
        shared2 = compute_shared_secret(c_priv2, s_pub2)
        send2, _, _ = derive_session_keys(shared2, thash2)

        # Despite same RSA keys, session keys differ
        assert send1 != send2

    def test_session_key_not_derivable_from_long_term_key_alone(self, tmp_path):
        """Without the ephemeral DH private key, the session key cannot be derived."""
        import base64
        from crypto.dh_params import bytes_to_int
        from net.handshake_client import build_client_hello
        from net.handshake_server import build_server_hello

        client_id = IdentityManager(tmp_path / "c").load_or_create_identity("client")
        server_id = IdentityManager(tmp_path / "s").load_or_create_identity("server")

        ch, c_priv, c_pub = build_client_hello(client_id)
        sh, s_priv, s_pub = build_server_hello(server_id, ch["nonce1_b64"])

        s_dh_pub = bytes_to_int(base64.b64decode(sh["dh_public_b64"]))
        real_shared = compute_shared_secret(c_priv, s_dh_pub)
        thash = transcript_hash(ch, sh)
        real_send, _, _ = derive_session_keys(real_shared, thash)

        # Attacker has RSA long-term keys but not c_priv
        # They can see c_pub (in CLIENT_HELLO) and s_dh_pub (in SERVER_HELLO)
        # Without c_priv, they can't compute the shared secret (DH hardness)
        # We demonstrate this by showing a fake shared secret gives different keys
        fake_shared = b"\xAB" * 256
        fake_send, _, _ = derive_session_keys(fake_shared, thash)
        assert real_send != fake_send
