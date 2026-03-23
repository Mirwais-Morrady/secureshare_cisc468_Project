import sys
from pathlib import Path
import pytest

BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE_DIR))

from net.framing import encode_frame, decode_frame, FramingError
import io


class TestFraming:

    def test_encode_frame_produces_4_byte_header(self):
        payload = b"hello"
        frame = encode_frame(payload)
        assert len(frame) == 4 + len(payload)
        import struct
        length = struct.unpack(">I", frame[:4])[0]
        assert length == len(payload)

    def test_decode_frame_roundtrip(self):
        payload = b"test message"
        frame = encode_frame(payload)
        stream = io.BytesIO(frame)
        result = decode_frame(stream)
        assert result == payload

    def test_decode_frame_empty_payload(self):
        payload = b""
        frame = encode_frame(payload)
        stream = io.BytesIO(frame)
        result = decode_frame(stream)
        assert result == payload

    def test_decode_frame_large_payload(self):
        payload = b"x" * 100000
        frame = encode_frame(payload)
        stream = io.BytesIO(frame)
        result = decode_frame(stream)
        assert result == payload

    def test_decode_frame_eof_raises_error(self):
        frame = encode_frame(b"hello")
        stream = io.BytesIO(frame[:3])  # Truncated header
        with pytest.raises(FramingError):
            decode_frame(stream)

    def test_encode_decode_json_message(self):
        import json
        msg = {"type": "PING", "proto_ver": "1.0"}
        payload = json.dumps(msg).encode()
        frame = encode_frame(payload)
        stream = io.BytesIO(frame)
        result = decode_frame(stream)
        decoded = json.loads(result)
        assert decoded["type"] == "PING"
