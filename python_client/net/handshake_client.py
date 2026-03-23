
import base64
import os

from protocol.handshake import generate_dh_keypair, compute_shared_secret, derive_session_keys, transcript_hash
from protocol.serializer import json_dumps_bytes, json_loads_bytes
from crypto.identity import IdentityManager
from crypto.dh_params import bytes_to_int
from crypto.session import SecureSession
from net.framing import encode_frame, decode_frame


def build_client_hello(identity):
    priv, pub = generate_dh_keypair()
    nonce = os.urandom(16)

    msg = {
        "type": "CLIENT_HELLO",
        "proto_ver": "1.0",
        "peer_name": identity.peer_name,
        "peer_id": identity.peer_id,
        "rsa_public_key_der_b64": base64.b64encode(identity.public_key_der).decode(),
        "dh_public_b64": base64.b64encode(pub.to_bytes(256, "big")).decode(),
        "nonce1_b64": base64.b64encode(nonce).decode(),
    }

    sig = IdentityManager.sign(identity.private_key, json_dumps_bytes(msg))
    msg["signature_b64"] = base64.b64encode(sig).decode()

    return msg, priv, pub


def execute_client_handshake(sock, identity):
    """
    Perform the full CLIENT_HELLO -> SERVER_HELLO handshake as initiator.
    Returns a SecureSession on success, or raises on failure.
    """
    from cryptography.hazmat.primitives import serialization

    stream = sock.makefile("rb")

    # Build and send CLIENT_HELLO
    client_hello, dh_priv, dh_pub = build_client_hello(identity)
    payload = json_dumps_bytes(client_hello)
    sock.sendall(encode_frame(payload))

    # Receive SERVER_HELLO
    raw = decode_frame(stream)
    server_hello = json_loads_bytes(raw)

    if server_hello.get("type") != "SERVER_HELLO":
        raise ValueError(f"Expected SERVER_HELLO, got: {server_hello.get('type')}")

    if server_hello.get("proto_ver") != "1.0":
        raise ValueError(f"Unsupported protocol version: {server_hello.get('proto_ver')}")

    # Verify SERVER_HELLO signature
    server_pub_der = base64.b64decode(server_hello["rsa_public_key_der_b64"])
    server_pub_key = serialization.load_der_public_key(server_pub_der)

    unsigned = {k: v for k, v in server_hello.items() if k != "signature_b64"}
    sig_bytes = base64.b64decode(server_hello["signature_b64"])
    signed_data = json_dumps_bytes(unsigned)
    IdentityManager.verify(server_pub_key, signed_data, sig_bytes)

    # Derive session keys
    server_dh_pub_bytes = base64.b64decode(server_hello["dh_public_b64"])
    server_dh_pub_int = bytes_to_int(server_dh_pub_bytes)
    shared_secret = compute_shared_secret(dh_priv, server_dh_pub_int)
    thash = transcript_hash(client_hello, server_hello)
    send_key, recv_key, session_id = derive_session_keys(shared_secret, thash)

    return SecureSession(session_id, send_key, recv_key), server_hello
