
import base64
import os

from protocol.handshake import generate_dh_keypair, compute_shared_secret, derive_session_keys, transcript_hash
from protocol.serializer import json_dumps_bytes, json_loads_bytes
from crypto.identity import IdentityManager
from crypto.dh_params import bytes_to_int
from crypto.session import SecureSession
from net.framing import encode_frame, decode_frame


def build_server_hello(identity, client_nonce):
    priv, pub = generate_dh_keypair()
    nonce = os.urandom(16)

    msg = {
        "type": "SERVER_HELLO",
        "proto_ver": "1.0",
        "peer_name": identity.peer_name,
        "peer_id": identity.peer_id,
        "rsa_public_key_der_b64": base64.b64encode(identity.public_key_der).decode(),
        "dh_public_b64": base64.b64encode(pub.to_bytes(256, "big")).decode(),
        "nonce2_b64": base64.b64encode(nonce).decode(),
        "client_nonce1_b64": client_nonce,
    }

    sig = IdentityManager.sign(identity.private_key, json_dumps_bytes(msg))
    msg["signature_b64"] = base64.b64encode(sig).decode()

    return msg, priv, pub


def execute_server_handshake(sock, identity):
    """
    Perform the full SERVER side of the handshake (receive CLIENT_HELLO, send SERVER_HELLO).
    Returns a SecureSession on success, or raises on failure.
    """
    from cryptography.hazmat.primitives import serialization

    stream = sock.makefile("rb")

    # Receive CLIENT_HELLO
    raw = decode_frame(stream)
    client_hello = json_loads_bytes(raw)

    if client_hello.get("type") != "CLIENT_HELLO":
        raise ValueError(f"Expected CLIENT_HELLO, got: {client_hello.get('type')}")

    if client_hello.get("proto_ver") != "1.0":
        raise ValueError(f"Unsupported protocol version: {client_hello.get('proto_ver')}")

    # Verify CLIENT_HELLO signature
    client_pub_der = base64.b64decode(client_hello["rsa_public_key_der_b64"])
    client_pub_key = serialization.load_der_public_key(client_pub_der)

    unsigned = {k: v for k, v in client_hello.items() if k != "signature_b64"}
    sig_bytes = base64.b64decode(client_hello["signature_b64"])
    signed_data = json_dumps_bytes(unsigned)
    IdentityManager.verify(client_pub_key, signed_data, sig_bytes)

    # Build and send SERVER_HELLO
    client_nonce = client_hello["nonce1_b64"]
    server_hello, dh_priv, dh_pub = build_server_hello(identity, client_nonce)
    payload = json_dumps_bytes(server_hello)
    sock.sendall(encode_frame(payload))

    # Derive session keys
    client_dh_pub_bytes = base64.b64decode(client_hello["dh_public_b64"])
    client_dh_pub_int = bytes_to_int(client_dh_pub_bytes)
    shared_secret = compute_shared_secret(dh_priv, client_dh_pub_int)
    thash = transcript_hash(client_hello, server_hello)
    # derive_session_keys returns (client_to_server, server_to_client, session_id)
    # Server sends on server_to_client channel, receives on client_to_server channel
    c2s_key, s2c_key, session_id = derive_session_keys(shared_secret, thash)
    return SecureSession(session_id, s2c_key, c2s_key), client_hello
