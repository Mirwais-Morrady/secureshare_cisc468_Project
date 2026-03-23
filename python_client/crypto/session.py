
import base64, os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from protocol.canonical_json import canonical_json_bytes


@dataclass
class SecureSession:
    session_id: str
    send_key: bytes
    recv_key: bytes
    send_seq: int = 0
    recv_seq: int = 0


def build_aad(version, session_id, seq, msg_type):
    return canonical_json_bytes({
        "version": version,
        "session_id": session_id,
        "msg_seq": seq,
        "msg_type": msg_type,
    })


def encrypt(session: SecureSession, msg_type: str, plaintext: bytes):
    session.send_seq += 1
    seq = session.send_seq
    nonce = os.urandom(12)

    aad = build_aad("1.0", session.session_id, seq, msg_type)
    aes = AESGCM(session.send_key)
    ct = aes.encrypt(nonce, plaintext, aad)

    return {
        "version": "1.0",
        "session_id": session.session_id,
        "msg_seq": seq,
        "msg_type": msg_type,
        "nonce_b64": base64.b64encode(nonce).decode(),
        "aad_b64": base64.b64encode(aad).decode(),
        "ciphertext_b64": base64.b64encode(ct).decode(),
    }


def decrypt(session: SecureSession, env: dict):
    nonce = base64.b64decode(env["nonce_b64"])
    aad = base64.b64decode(env["aad_b64"])
    ct = base64.b64decode(env["ciphertext_b64"])

    # Replay / out-of-order protection: sequence number must advance
    incoming_seq = env.get("msg_seq", 0)
    if incoming_seq <= session.recv_seq:
        raise ValueError(
            f"Replay or out-of-order message rejected: "
            f"incoming seq={incoming_seq} <= expected seq>{session.recv_seq}"
        )

    aes = AESGCM(session.recv_key)
    plaintext = aes.decrypt(nonce, ct, aad)

    # Only advance the counter after successful decryption
    session.recv_seq = incoming_seq
    return plaintext
