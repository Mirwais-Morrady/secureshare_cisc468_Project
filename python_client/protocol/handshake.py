
import os, base64
from crypto.dh_params import GROUP14_P, GROUP14_G, int_to_bytes, bytes_to_int
from crypto.hkdf_utils import hkdf_sha256
from crypto.hashing import sha256_bytes
from protocol.canonical_json import canonical_json_bytes

def generate_dh_keypair():
    private = int.from_bytes(os.urandom(32), "big")
    public = pow(GROUP14_G, private, GROUP14_P)
    return private, public

def compute_shared_secret(private, peer_public):
    shared = pow(peer_public, private, GROUP14_P)
    return int_to_bytes(shared)

def derive_session_keys(shared_secret, transcript_hash):
    send_key = hkdf_sha256(shared_secret, transcript_hash, b"cisc468/session/client_to_server", 32)
    recv_key = hkdf_sha256(shared_secret, transcript_hash, b"cisc468/session/server_to_client", 32)
    session_id = hkdf_sha256(shared_secret, transcript_hash, b"cisc468/session/session_id", 16)
    return send_key, recv_key, session_id.hex()

def transcript_hash(client_hello: dict, server_hello: dict):
    data = canonical_json_bytes(client_hello) + canonical_json_bytes(server_hello)
    return sha256_bytes(data)
