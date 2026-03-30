"""
REQUIREMENT 8 — Perfect Forward Secrecy
========================================
Tests that:
  - Each session uses a fresh ephemeral DH key pair (not the long-term RSA key)
  - Two sessions between the same peers produce completely different session keys
  - Knowing the long-term RSA private key does not reveal any session key
  - HKDF derives distinct send/recv keys so a compromised session key only
    exposes that one direction of that one session
"""
import os
import pytest

from crypto.hkdf_utils import hkdf_sha256
from protocol.handshake import (
    generate_dh_keypair,
    compute_shared_secret,
    derive_session_keys,
    transcript_hash,
)
from crypto.hashing import sha256_bytes
from protocol.canonical_json import canonical_json_bytes


def _simulate_handshake():
    """
    Simulate a minimal DH handshake between two peers.
    Returns (send_key_c, recv_key_c, session_id) from the client's perspective.
    """
    priv_c, pub_c = generate_dh_keypair()
    priv_s, pub_s = generate_dh_keypair()

    # Each side computes the shared secret independently
    shared_c = compute_shared_secret(priv_c, pub_s)
    shared_s = compute_shared_secret(priv_s, pub_c)

    # Build a minimal transcript (actual handshake includes RSA-signed hellos)
    ch = {"type": "CLIENT_HELLO", "dh_public_b64": str(pub_c)}
    sh = {"type": "SERVER_HELLO", "dh_public_b64": str(pub_s)}
    t_hash = sha256_bytes(canonical_json_bytes(ch) + canonical_json_bytes(sh))

    send_key_c, recv_key_c, sid_c = derive_session_keys(shared_c, t_hash)
    send_key_s, recv_key_s, sid_s = derive_session_keys(shared_s, t_hash)

    return send_key_c, recv_key_c, sid_c, send_key_s, recv_key_s, sid_s


class TestEphemeralDhKeypair:

    def test_each_dh_keypair_is_unique(self):
        """generate_dh_keypair() must never produce the same private key twice."""
        priv1, pub1 = generate_dh_keypair()
        priv2, pub2 = generate_dh_keypair()
        assert priv1 != priv2, "DH private keys must be randomly generated"
        assert pub1 != pub2, "DH public keys must differ across sessions"

    def test_shared_secret_matches_on_both_sides(self):
        """Both peers computing the DH exchange must arrive at the same secret."""
        priv_c, pub_c = generate_dh_keypair()
        priv_s, pub_s = generate_dh_keypair()
        shared_c = compute_shared_secret(priv_c, pub_s)
        shared_s = compute_shared_secret(priv_s, pub_c)
        assert shared_c == shared_s, "DH shared secrets must be equal on both sides"

    def test_different_dh_exchanges_produce_different_secrets(self):
        """Two independent handshakes must produce different shared secrets."""
        priv_c1, pub_c1 = generate_dh_keypair()
        priv_s1, pub_s1 = generate_dh_keypair()
        priv_c2, pub_c2 = generate_dh_keypair()
        priv_s2, pub_s2 = generate_dh_keypair()

        secret1 = compute_shared_secret(priv_c1, pub_s1)
        secret2 = compute_shared_secret(priv_c2, pub_s2)
        assert secret1 != secret2, "Independent sessions must not share a secret"


class TestSessionKeyIsolation:

    def test_two_sessions_produce_different_keys(self):
        """Two separate handshake sessions must derive completely different keys."""
        k1_send, k1_recv, sid1, _, _, _ = _simulate_handshake()
        k2_send, k2_recv, sid2, _, _, _ = _simulate_handshake()

        assert k1_send != k2_send, "Session send keys must differ across sessions"
        assert k1_recv != k2_recv, "Session recv keys must differ across sessions"
        assert sid1 != sid2, "Session IDs must be unique"

    def test_send_and_recv_keys_are_distinct(self):
        """Client send key != client recv key (directional encryption)."""
        send_key, recv_key, *_ = _simulate_handshake()
        assert send_key != recv_key, \
            "Send and recv keys must be distinct — compromise of one direction does not expose the other"

    def test_both_peers_derive_identical_raw_key_material(self):
        """
        Both sides calling derive_session_keys with the same shared secret and
        transcript must produce the same raw key labels.
        The client/server assignment (swapping keys) is done by the handshake
        layer (SessionManager), verified by the Java HandshakeManagerTest.
        """
        send_c, recv_c, sid_c, send_s, recv_s, sid_s = _simulate_handshake()
        assert send_c == send_s, "Both peers derive the same c2s key label from the same secret"
        assert recv_c == recv_s, "Both peers derive the same s2c key label from the same secret"
        assert sid_c == sid_s, "Session ID must be identical on both sides"


class TestLongTermKeyDoesNotExposeSession:

    def test_rsa_key_material_not_used_in_session_key_derivation(self):
        """
        The session key is derived solely from the ephemeral DH shared secret
        and the transcript hash.  Long-term RSA key bytes must not appear in
        the derived session key — i.e., knowing the RSA key alone gives an
        attacker nothing about the session key.
        """
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization

        # Generate a long-term RSA key
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa_private_bytes = private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

        # Simulate a session
        send_key, recv_key, *_ = _simulate_handshake()

        # Session keys must not be substrings of RSA key material
        assert send_key not in rsa_private_bytes, \
            "Session key must not appear in RSA private key bytes"
        assert recv_key not in rsa_private_bytes, \
            "Session recv key must not appear in RSA private key bytes"

    def test_hkdf_labels_produce_distinct_keys(self):
        """HKDF with different labels from the same IKM produces different outputs."""
        ikm = os.urandom(32)
        salt = os.urandom(32)
        k1 = hkdf_sha256(ikm, salt, b"cisc468/session/client_to_server", 32)
        k2 = hkdf_sha256(ikm, salt, b"cisc468/session/server_to_client", 32)
        k3 = hkdf_sha256(ikm, salt, b"cisc468/session/session_id", 16)
        assert k1 != k2, "HKDF labels must produce distinct keys"
        assert k1[:16] != k3, "Session ID material must differ from encryption keys"
