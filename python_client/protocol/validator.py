from typing import Dict, Any


SERVER_HELLO_FIELDS = [
    "type",
    "proto_ver",
    "peer_name",
    "peer_id",
    "rsa_public_key_der_b64",
    "dh_public_b64",
    "nonce2_b64",
    "client_nonce1_b64",
    "signature_b64",
]


def validate_hello_message(message: Dict[str, Any], expected_type: str) -> bool:
    if not isinstance(message, dict):
        raise ValueError("Message must be a dictionary")

    if message.get("type") != expected_type:
        raise ValueError(f"Expected message type {expected_type}")

    if expected_type == "SERVER_HELLO":
        validate_server_hello(message)

    return True


def validate_server_hello(message: Dict[str, Any]) -> bool:
    for field in SERVER_HELLO_FIELDS:
        if field not in message:
            raise ValueError(f"Missing required field: {field}")

    if message["proto_ver"] != "1.0":
        raise ValueError("Unsupported protocol version")

    return True