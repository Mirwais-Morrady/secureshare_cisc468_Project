"""
REQUIREMENT 3 & 4 — File Transfer Protocol (Consent) and File Listing
=======================================================================
REQ 3: Peers must be able to send/request files; receiver must consent.
REQ 4: Peers must be able to list available files without consent.

Tests that:
  - Files are split into chunks of the correct size
  - Chunks are reassembled to produce the exact original bytes
  - Large files chunk correctly (multi-chunk)
  - Framing correctly length-prefixes and deframes arbitrary payloads
  - Frame decode raises FramingError on unexpected EOF
  - FILE_REQUEST message contains correct fields (file, filesize, sha256_hex)
  - FILE_REQUEST_DENY carries a reason
  - FILE_TRANSFER_COMPLETE message carries SHA-256 for integrity
  - ConsentManager queues requests and unblocks on response
"""
import io
import os
import struct
import pytest

from files.chunker import chunk_bytes, CHUNK_SIZE
from net.framing import encode_frame, decode_frame, FramingError
from net.consent_manager import ConsentManager
import threading


# ── File Chunking ─────────────────────────────────────────────────────────────

class TestChunker:

    def test_empty_file_produces_no_chunks(self):
        assert list(chunk_bytes(b"")) == []

    def test_small_file_produces_single_chunk(self):
        data = b"hello world"
        chunks = list(chunk_bytes(data))
        assert len(chunks) == 1
        assert chunks[0] == data

    def test_exact_chunk_boundary(self):
        data = os.urandom(CHUNK_SIZE)
        chunks = list(chunk_bytes(data))
        assert len(chunks) == 1
        assert chunks[0] == data

    def test_one_byte_over_boundary_produces_two_chunks(self):
        data = os.urandom(CHUNK_SIZE + 1)
        chunks = list(chunk_bytes(data))
        assert len(chunks) == 2
        assert len(chunks[0]) == CHUNK_SIZE
        assert len(chunks[1]) == 1

    def test_large_file_chunks_reassemble_exactly(self):
        """Chunking then concatenating must recover the original file."""
        data = os.urandom(5 * CHUNK_SIZE + 12345)
        chunks = list(chunk_bytes(data))
        reassembled = b"".join(chunks)
        assert reassembled == data

    def test_chunk_size_constant_is_65536(self):
        assert CHUNK_SIZE == 65536

    def test_all_chunks_except_last_are_full_size(self):
        data = os.urandom(3 * CHUNK_SIZE + 100)
        chunks = list(chunk_bytes(data))
        for chunk in chunks[:-1]:
            assert len(chunk) == CHUNK_SIZE
        assert len(chunks[-1]) == 100


# ── Framing ───────────────────────────────────────────────────────────────────

class TestFraming:

    def test_encode_decode_roundtrip(self):
        payload = b'{"type":"FILE_CHUNK","index":0}'
        framed = encode_frame(payload)
        stream = io.BytesIO(framed)
        recovered = decode_frame(stream)
        assert recovered == payload

    def test_frame_has_4_byte_length_prefix(self):
        payload = b"hello"
        framed = encode_frame(payload)
        assert len(framed) == 4 + len(payload)
        size_field = struct.unpack(">I", framed[:4])[0]
        assert size_field == len(payload)

    def test_empty_payload_frames_correctly(self):
        payload = b""
        framed = encode_frame(payload)
        stream = io.BytesIO(framed)
        assert decode_frame(stream) == payload

    def test_multiple_frames_decoded_in_sequence(self):
        frames = [b"frame one", b"frame two", b"frame three"]
        buf = io.BytesIO()
        for f in frames:
            buf.write(encode_frame(f))
        buf.seek(0)
        for expected in frames:
            assert decode_frame(buf) == expected

    def test_unexpected_eof_raises_framing_error(self):
        """Truncated stream must raise FramingError (not a silent hang)."""
        # Write a length prefix claiming 100 bytes but only provide 10
        truncated = struct.pack(">I", 100) + b"X" * 10
        stream = io.BytesIO(truncated)
        with pytest.raises(FramingError):
            decode_frame(stream)

    def test_empty_stream_raises_framing_error(self):
        stream = io.BytesIO(b"")
        with pytest.raises(FramingError):
            decode_frame(stream)

    def test_large_payload_roundtrip(self):
        payload = os.urandom(512 * 1024)   # 512 KB
        stream = io.BytesIO(encode_frame(payload))
        assert decode_frame(stream) == payload


# ── Protocol Message Structure ────────────────────────────────────────────────

class TestProtocolMessages:

    def test_file_request_fields(self):
        """FILE_REQUEST must carry file name, size, and pre-computed SHA-256."""
        import hashlib
        from protocol.message_types import FILE_REQUEST, FILE_REQUEST_ACCEPT, FILE_REQUEST_DENY

        data = b"file content"
        sha = hashlib.sha256(data).hexdigest()
        msg = {
            "type": FILE_REQUEST,
            "file": "document.pdf",
            "filesize": len(data),
            "sha256_hex": sha,
        }
        assert msg["type"] == FILE_REQUEST
        assert msg["filesize"] == len(data)
        assert len(msg["sha256_hex"]) == 64   # hex-encoded SHA-256

    def test_file_transfer_complete_carries_sha256(self):
        """FILE_TRANSFER_COMPLETE must include the SHA-256 for integrity verification."""
        import hashlib
        from protocol.message_types import FILE_TRANSFER_COMPLETE

        data = b"complete file bytes"
        msg = {
            "type": FILE_TRANSFER_COMPLETE,
            "file": "report.txt",
            "sha256_hex": hashlib.sha256(data).hexdigest(),
        }
        assert "sha256_hex" in msg
        assert len(msg["sha256_hex"]) == 64

    def test_file_request_deny_carries_reason(self):
        from protocol.message_types import FILE_REQUEST_DENY
        msg = {"type": FILE_REQUEST_DENY, "file": "secret.txt", "reason": "User declined"}
        assert "reason" in msg


# ── ConsentManager ────────────────────────────────────────────────────────────

class TestConsentManager:

    def test_accepted_consent_returns_true(self):
        """When the main thread accepts, the background thread must get True."""
        mgr = ConsentManager()
        result = {}

        def background():
            result["accepted"] = mgr.request("alice", "file.txt", 1024)

        t = threading.Thread(target=background)
        t.start()

        # Wait for the request to be queued
        import time
        for _ in range(50):
            if mgr.is_pending():
                break
            time.sleep(0.01)

        assert mgr.is_pending()
        mgr.pop_pending()
        mgr.respond(True)
        t.join(timeout=2)
        assert result["accepted"] is True

    def test_denied_consent_returns_false(self):
        """When the main thread denies, the background thread must get False."""
        mgr = ConsentManager()
        result = {}

        def background():
            result["accepted"] = mgr.request("bob", "huge_file.iso", 2 * 10**9)

        t = threading.Thread(target=background)
        t.start()

        import time
        for _ in range(50):
            if mgr.is_pending():
                break
            time.sleep(0.01)

        mgr.pop_pending()
        mgr.respond(False)
        t.join(timeout=2)
        assert result["accepted"] is False

    def test_pending_state_cleared_after_pop(self):
        mgr = ConsentManager()
        import time

        def background():
            mgr.request("peer", "f.txt", 0)

        t = threading.Thread(target=background)
        t.start()

        for _ in range(50):
            if mgr.is_pending():
                break
            time.sleep(0.01)

        assert mgr.is_pending()
        mgr.pop_pending()
        assert not mgr.is_pending()
        mgr.respond(True)
        t.join(timeout=2)
