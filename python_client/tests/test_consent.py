"""
Tests for consent-based file transfer protocol (Requirement 3).

The consent flow:
  Sender → FILE_REQUEST {file, filesize, sha256_hex}
  Receiver → FILE_REQUEST_ACCEPT or FILE_REQUEST_DENY
  (If ACCEPT) Sender → FILE_CHUNK * N → FILE_TRANSFER_COMPLETE
"""
import sys
from pathlib import Path
import pytest

BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE_DIR))

from protocol.message_types import (
    FILE_REQUEST, FILE_REQUEST_ACCEPT, FILE_REQUEST_DENY,
    FILE_CHUNK, FILE_TRANSFER_COMPLETE,
)


class TestConsentMessages:

    def test_file_request_message_structure(self):
        """FILE_REQUEST must include file name, size, and SHA-256."""
        msg = {
            "type": FILE_REQUEST,
            "file": "secret.txt",
            "filesize": 1024,
            "sha256_hex": "a" * 64,
        }
        assert msg["type"] == FILE_REQUEST
        assert "file" in msg
        assert "filesize" in msg
        assert "sha256_hex" in msg

    def test_file_request_accept_message_structure(self):
        msg = {"type": FILE_REQUEST_ACCEPT, "file": "secret.txt"}
        assert msg["type"] == FILE_REQUEST_ACCEPT
        assert msg["file"] == "secret.txt"

    def test_file_request_deny_message_structure(self):
        msg = {"type": FILE_REQUEST_DENY, "file": "secret.txt", "reason": "User declined"}
        assert msg["type"] == FILE_REQUEST_DENY
        assert "reason" in msg

    def test_file_chunk_message_structure(self):
        msg = {"type": FILE_CHUNK, "file": "secret.txt", "index": 0, "data": "deadbeef"}
        assert msg["type"] == FILE_CHUNK
        assert "index" in msg
        assert "data" in msg

    def test_transfer_complete_has_integrity_hash(self):
        """FILE_TRANSFER_COMPLETE must carry SHA-256 for integrity verification."""
        msg = {
            "type": FILE_TRANSFER_COMPLETE,
            "file": "secret.txt",
            "sha256_hex": "b" * 64,
        }
        assert msg["type"] == FILE_TRANSFER_COMPLETE
        assert len(msg["sha256_hex"]) == 64


class TestTransferManager:
    """Tests for the TransferManager send flow."""

    def test_transfer_manager_sends_file_request_first(self, tmp_path):
        """Verify TransferManager sends FILE_REQUEST before any data."""
        import socket, threading, io
        from crypto.identity import IdentityManager
        from net.handshake_client import execute_client_handshake
        from net.handshake_server import execute_server_handshake
        from files.transfer_manager import TransferManager
        from net.framing import decode_frame
        from protocol.serializer import json_loads_bytes
        from crypto.session import decrypt

        port = _free_port()
        client_id = IdentityManager(tmp_path / "c").load_or_create_identity("client")
        server_id = IdentityManager(tmp_path / "s").load_or_create_identity("server")

        received_messages = []
        server_ready = threading.Event()

        def run_server():
            srv = socket.socket()
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", port))
            srv.listen(1)
            server_ready.set()
            conn, _ = srv.accept()
            session, _ = execute_server_handshake(conn, server_id)

            # Read and collect all incoming messages
            stream = conn.makefile("rb")
            from net.framing import FramingError
            try:
                while True:
                    raw = decode_frame(stream)
                    env = json_loads_bytes(raw)
                    pt = decrypt(session, env)
                    msg = json_loads_bytes(pt)
                    received_messages.append(msg)
                    if msg.get("type") == FILE_REQUEST:
                        # Respond ACCEPT
                        from crypto.session import encrypt
                        from net.framing import encode_frame
                        from protocol.serializer import json_dumps_bytes
                        accept = {"type": FILE_REQUEST_ACCEPT, "file": msg["file"]}
                        env2 = encrypt(session, FILE_REQUEST_ACCEPT, json_dumps_bytes(accept))
                        conn.sendall(encode_frame(json_dumps_bytes(env2)))
                    if msg.get("type") == FILE_TRANSFER_COMPLETE:
                        break
            except FramingError:
                pass
            srv.close()

        t = threading.Thread(target=run_server)
        t.start()
        server_ready.wait()

        test_file = tmp_path / "file.txt"
        test_file.write_bytes(b"hello world")

        client_sock = socket.socket()
        client_sock.connect(("127.0.0.1", port))
        session, _ = execute_client_handshake(client_sock, client_id)
        mgr = TransferManager(client_sock, session, "server")
        result = mgr.send_file(test_file)
        client_sock.close()
        t.join(timeout=5)

        assert result is True
        assert received_messages[0]["type"] == FILE_REQUEST  # consent first!
        assert any(m["type"] == FILE_CHUNK for m in received_messages)
        assert received_messages[-1]["type"] == FILE_TRANSFER_COMPLETE

    def test_transfer_manager_respects_deny(self, tmp_path):
        """Verify TransferManager stops if the peer denies the request."""
        import socket, threading
        from crypto.identity import IdentityManager
        from net.handshake_client import execute_client_handshake
        from net.handshake_server import execute_server_handshake
        from files.transfer_manager import TransferManager

        port = _free_port()
        client_id = IdentityManager(tmp_path / "c").load_or_create_identity("client")
        server_id = IdentityManager(tmp_path / "s").load_or_create_identity("server")
        server_ready = threading.Event()

        def run_server():
            srv = socket.socket()
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", port))
            srv.listen(1)
            server_ready.set()
            conn, _ = srv.accept()
            session, _ = execute_server_handshake(conn, server_id)

            from net.framing import decode_frame, FramingError
            from protocol.serializer import json_loads_bytes, json_dumps_bytes
            from crypto.session import decrypt, encrypt
            from net.framing import encode_frame
            stream = conn.makefile("rb")
            try:
                raw = decode_frame(stream)
                env = json_loads_bytes(raw)
                pt = decrypt(session, env)
                msg = json_loads_bytes(pt)
                if msg.get("type") == FILE_REQUEST:
                    deny = {"type": FILE_REQUEST_DENY, "file": msg["file"], "reason": "No thanks"}
                    env2 = encrypt(session, FILE_REQUEST_DENY, json_dumps_bytes(deny))
                    conn.sendall(encode_frame(json_dumps_bytes(env2)))
            except FramingError:
                pass
            srv.close()

        t = threading.Thread(target=run_server)
        t.start()
        server_ready.wait()

        test_file = tmp_path / "file.txt"
        test_file.write_bytes(b"data")

        client_sock = socket.socket()
        client_sock.connect(("127.0.0.1", port))
        session, _ = execute_client_handshake(client_sock, client_id)
        mgr = TransferManager(client_sock, session, "server")
        result = mgr.send_file(test_file)
        client_sock.close()
        t.join(timeout=5)

        assert result is False  # Transfer was denied


def _free_port():
    import socket as s
    with s.socket() as sock:
        sock.bind(("", 0))
        return sock.getsockname()[1]
