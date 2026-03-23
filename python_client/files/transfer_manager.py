"""
Transfer manager: sends files to peers over an established SecureSession.

Handles:
- Requesting consent from the remote peer before sending
- Splitting the file into chunks
- Sending each chunk through the encrypted secure channel
- Attaching SHA-256 integrity hash to the final transfer-complete message
"""
import hashlib
from pathlib import Path

from crypto.session import encrypt, decrypt
from files.chunker import chunk_bytes
from net.framing import decode_frame, encode_frame
from protocol.message_types import (
    FILE_REQUEST, FILE_REQUEST_ACCEPT, FILE_REQUEST_DENY,
    FILE_CHUNK, FILE_TRANSFER_COMPLETE,
)
from protocol.serializer import json_dumps_bytes, json_loads_bytes


class TransferManager:
    """Manages outgoing file transfers over an established SecureSession."""

    def __init__(self, conn, session, peer_name: str):
        self.conn = conn
        self.session = session
        self.peer_name = peer_name
        self._stream = conn.makefile("rb")

    def send_file(self, file_path: Path) -> bool:
        """
        Request consent then send a file to the connected peer.

        Args:
            file_path: Path to the file to send

        Returns:
            bool: True if transfer completed successfully, False if denied or failed
        """
        data = file_path.read_bytes()
        filesize = len(data)
        filename = file_path.name
        sha256_hex = hashlib.sha256(data).hexdigest()

        # 1. Send FILE_REQUEST and wait for consent
        self._send({"type": FILE_REQUEST, "file": filename, "filesize": filesize,
                    "sha256_hex": sha256_hex})

        response = self._recv()
        if response.get("type") == FILE_REQUEST_DENY:
            reason = response.get("reason", "no reason given")
            print(f"[INFO] {self.peer_name} declined '{filename}': {reason}")
            return False
        if response.get("type") != FILE_REQUEST_ACCEPT:
            print(f"[ERROR] Unexpected response to FILE_REQUEST: {response.get('type')}")
            return False

        print(f"[INFO] {self.peer_name} accepted '{filename}', sending {filesize:,} bytes...")

        # 2. Send chunks
        for i, chunk in enumerate(chunk_bytes(data)):
            self._send({
                "type": FILE_CHUNK,
                "file": filename,
                "index": i,
                "data": chunk.hex(),
            })

        # 3. Send transfer-complete with SHA-256 for integrity verification
        self._send({
            "type": FILE_TRANSFER_COMPLETE,
            "file": filename,
            "sha256_hex": sha256_hex,
        })

        print(f"[INFO] '{filename}' sent successfully (SHA-256: {sha256_hex[:16]}...)")
        return True

    def _send(self, msg: dict):
        msg_type = msg.get("type", "UNKNOWN")
        plaintext = json_dumps_bytes(msg)
        envelope = encrypt(self.session, msg_type, plaintext)
        payload = json_dumps_bytes(envelope)
        self.conn.sendall(encode_frame(payload))

    def _recv(self) -> dict:
        raw = decode_frame(self._stream)
        envelope = json_loads_bytes(raw)
        plaintext = decrypt(self.session, envelope)
        return json_loads_bytes(plaintext)
