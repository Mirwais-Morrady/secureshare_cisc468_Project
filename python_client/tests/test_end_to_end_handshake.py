"""
End-to-end Python handshake test.

Tests that Python can act as both client and server,
performing a complete handshake over a real TCP connection.
"""
import sys
from pathlib import Path
import socket
import threading
import time
import pytest

BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE_DIR))

from crypto.identity import IdentityManager
from net.handshake_client import execute_client_handshake
from net.handshake_server import execute_server_handshake
from crypto.session import SecureSession, encrypt, decrypt
from protocol.serializer import json_dumps_bytes, json_loads_bytes


def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]


class TestEndToEndHandshake:

    def test_python_to_python_handshake(self, tmp_path):
        """Test that two Python peers can complete a full handshake."""
        port = find_free_port()

        client_id_dir = tmp_path / "client_identity"
        server_id_dir = tmp_path / "server_identity"

        client_mgr = IdentityManager(client_id_dir)
        server_mgr = IdentityManager(server_id_dir)

        client_identity = client_mgr.load_or_create_identity("client-peer")
        server_identity = server_mgr.load_or_create_identity("server-peer")

        server_session_ref = [None]
        server_error_ref = [None]

        def run_server():
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind(('127.0.0.1', port))
            server_sock.listen(1)
            conn, _ = server_sock.accept()
            try:
                session, client_hello = execute_server_handshake(conn, server_identity)
                server_session_ref[0] = session
            except Exception as e:
                server_error_ref[0] = e
            finally:
                conn.close()
                server_sock.close()

        server_thread = threading.Thread(target=run_server)
        server_thread.start()
        time.sleep(0.1)  # Wait for server to start

        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.connect(('127.0.0.1', port))

        client_session, server_hello = execute_client_handshake(client_sock, client_identity)
        client_sock.close()
        server_thread.join(timeout=5)

        assert server_error_ref[0] is None, f"Server error: {server_error_ref[0]}"
        assert client_session is not None
        assert server_session_ref[0] is not None

        client_session_obj = client_session
        server_session_obj = server_session_ref[0]

        # Verify session IDs match
        assert client_session_obj.session_id == server_session_obj.session_id

        # Verify keys are properly swapped
        assert client_session_obj.send_key == server_session_obj.recv_key
        assert client_session_obj.recv_key == server_session_obj.send_key

    def test_python_to_python_encrypted_exchange(self, tmp_path):
        """Test that two Python peers can exchange encrypted messages after handshake."""
        port = find_free_port()

        client_id_dir = tmp_path / "client_identity"
        server_id_dir = tmp_path / "server_identity"

        client_mgr = IdentityManager(client_id_dir)
        server_mgr = IdentityManager(server_id_dir)

        client_identity = client_mgr.load_or_create_identity("client-peer")
        server_identity = server_mgr.load_or_create_identity("server-peer")

        received_message = [None]
        server_error_ref = [None]

        def run_server():
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind(('127.0.0.1', port))
            server_sock.listen(1)
            conn, _ = server_sock.accept()
            try:
                session, _ = execute_server_handshake(conn, server_identity)
                # Receive encrypted message
                from net.framing import decode_frame
                from protocol.serializer import json_loads_bytes
                from crypto.session import decrypt
                stream = conn.makefile("rb")
                raw = decode_frame(stream)
                envelope = json_loads_bytes(raw)
                plaintext = decrypt(session, envelope)
                received_message[0] = json_loads_bytes(plaintext)
            except Exception as e:
                server_error_ref[0] = e
            finally:
                conn.close()
                server_sock.close()

        server_thread = threading.Thread(target=run_server)
        server_thread.start()
        time.sleep(0.1)

        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.connect(('127.0.0.1', port))

        client_session, _ = execute_client_handshake(client_sock, client_identity)

        # Send encrypted message
        from net.framing import encode_frame
        from crypto.session import encrypt
        msg = {"type": "PING", "data": "hello from client"}
        plaintext = json_dumps_bytes(msg)
        envelope = encrypt(client_session, "PING", plaintext)
        payload = json_dumps_bytes(envelope)
        client_sock.sendall(encode_frame(payload))
        client_sock.close()

        server_thread.join(timeout=5)

        assert server_error_ref[0] is None, f"Server error: {server_error_ref[0]}"
        assert received_message[0] is not None
        assert received_message[0]["type"] == "PING"
        assert received_message[0]["data"] == "hello from client"
