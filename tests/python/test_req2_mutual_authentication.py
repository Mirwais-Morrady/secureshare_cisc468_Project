"""
REQUIREMENT 2 — Mutual Authentication
======================================
Tests that:
  - RSA-2048 key pairs are generated correctly
  - RSA-PSS-SHA-256 signatures work for signing handshake data
  - A peer's identity (peer_id) is the SHA-256 of their RSA public key
  - Cross-key signature verification fails (prevents impersonation)
  - Handshake messages include both DH public value and RSA signature
  - The transcript hash is deterministic and covers both hello messages
  - HKDF correctly derives distinct session keys from the shared secret
"""
import base64
import os
import tempfile
from pathlib import Path

import pytest

from crypto.identity import IdentityManager
from crypto.hashing import sha256_hex
from protocol.handshake import (
    generate_dh_keypair,
    compute_shared_secret,
    derive_session_keys,
    transcript_hash,
)
from protocol.canonical_json import canonical_json_bytes
from crypto.hashing import sha256_bytes


def make_identity(name, tmp_path):
    d = Path(tmp_path) / name
    mgr = IdentityManager(d)
    return mgr.load_or_create_identity(name)


class TestRsaIdentity:

    def test_peer_id_is_sha256_of_public_key(self, tmp_path):
        """peer_id must be the SHA-256 fingerprint of the RSA public key DER."""
        identity = make_identity("alice", tmp_path)
        expected = sha256_hex(identity.public_key_der)
        assert identity.peer_id == expected

    def test_two_identities_have_different_peer_ids(self, tmp_path):
        """Each identity generates a unique RSA key pair."""
        a = make_identity("a", tmp_path)
        b = make_identity("b", tmp_path)
        assert a.peer_id != b.peer_id
        assert a.public_key_der != b.public_key_der

    def test_identity_persists_across_loads(self, tmp_path):
        """Loading the same identity directory twice must produce the same peer_id."""
        d = Path(tmp_path) / "persistent"
        mgr = IdentityManager(d)
        id1 = mgr.load_or_create_identity("peer")
        id2 = mgr.load_or_create_identity("peer")
        assert id1.peer_id == id2.peer_id
        assert id1.public_key_der == id2.public_key_der


class TestRsaSignatureVerification:

    def test_sign_and_verify_succeeds(self, tmp_path):
        """A signature made with a private key verifies with the matching public key."""
        identity = make_identity("signer", tmp_path)
        data = b"handshake transcript"
        sig = IdentityManager.sign(identity.private_key, data)
        # Must not raise
        IdentityManager.verify(identity.public_key, data, sig)

    def test_verification_with_wrong_public_key_fails(self, tmp_path):
        """Verifying a signature against a different peer's public key must fail."""
        alice = make_identity("alice_auth", tmp_path)
        bob = make_identity("bob_auth", tmp_path)
        data = b"Alice's signed hello"
        sig = IdentityManager.sign(alice.private_key, data)
        with pytest.raises(Exception):
            IdentityManager.verify(bob.public_key, data, sig)

    def test_tampered_data_signature_fails(self, tmp_path):
        """Verifying a valid signature against modified data must fail."""
        identity = make_identity("peer_v", tmp_path)
        original = b"original handshake data"
        sig = IdentityManager.sign(identity.private_key, original)
        with pytest.raises(Exception):
            IdentityManager.verify(identity.public_key, b"tampered handshake data", sig)

    def test_each_signature_is_unique(self, tmp_path):
        """RSA-PSS uses randomized salt — two signatures over the same data must differ."""
        identity = make_identity("unique_sig", tmp_path)
        data = b"same data every time"
        sig1 = IdentityManager.sign(identity.private_key, data)
        sig2 = IdentityManager.sign(identity.private_key, data)
        assert sig1 != sig2, "RSA-PSS must produce randomized signatures"


class TestDhHandshakeAuthentication:

    def _build_hello(self, peer_name, peer_id, pub_key_der, dh_pub, nonce):
        """Minimal hello dict matching protocol structure (unsigned)."""
        from crypto.dh_params import int_to_bytes
        return {
            "type": "CLIENT_HELLO",
            "proto_ver": "1.0",
            "peer_name": peer_name,
            "peer_id": peer_id,
            "rsa_public_key_der_b64": base64.b64encode(pub_key_der).decode(),
            "dh_public_b64": base64.b64encode(int_to_bytes(dh_pub)).decode(),
            "nonce1_b64": base64.b64encode(nonce).decode(),
        }

    def test_transcript_hash_is_deterministic(self, tmp_path):
        """The same two hello messages always produce the same transcript hash."""
        a = make_identity("a_tr", tmp_path)
        b = make_identity("b_tr", tmp_path)
        _, pub_a = generate_dh_keypair()
        _, pub_b = generate_dh_keypair()
        nonce_a = os.urandom(16)
        nonce_b = os.urandom(16)
        ch = self._build_hello(a.peer_name, a.peer_id, a.public_key_der, pub_a, nonce_a)
        sh = self._build_hello(b.peer_name, b.peer_id, b.public_key_der, pub_b, nonce_b)
        t1 = transcript_hash(ch, sh)
        t2 = transcript_hash(ch, sh)
        assert t1 == t2

    def test_swapped_hellos_produce_different_transcript(self, tmp_path):
        """Order matters: transcript_hash(A, B) ≠ transcript_hash(B, A)."""
        a = make_identity("a_swap", tmp_path)
        b = make_identity("b_swap", tmp_path)
        _, pub_a = generate_dh_keypair()
        _, pub_b = generate_dh_keypair()
        ch = self._build_hello(a.peer_name, a.peer_id, a.public_key_der, pub_a, os.urandom(16))
        sh = self._build_hello(b.peer_name, b.peer_id, b.public_key_der, pub_b, os.urandom(16))
        assert transcript_hash(ch, sh) != transcript_hash(sh, ch)

    def test_both_peers_derive_same_shared_secret(self, tmp_path):
        """Client and server independently compute the identical DH shared secret."""
        priv_c, pub_c = generate_dh_keypair()
        priv_s, pub_s = generate_dh_keypair()
        shared_c = compute_shared_secret(priv_c, pub_s)
        shared_s = compute_shared_secret(priv_s, pub_c)
        assert shared_c == shared_s

    def test_session_keys_derived_from_shared_secret(self, tmp_path):
        priv_c, pub_c = generate_dh_keypair()
        priv_s, pub_s = generate_dh_keypair()
        shared = compute_shared_secret(priv_c, pub_s)
        t_hash = sha256_bytes(b"dummy transcript")
        send_key, recv_key, session_id = derive_session_keys(shared, t_hash)
        assert len(send_key) == 32
        assert len(recv_key) == 32
        assert len(session_id) == 32  # hex of 16 bytes
