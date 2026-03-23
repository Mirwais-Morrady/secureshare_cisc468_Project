import struct

MAX_FRAME_SIZE = 16 * 1024 * 1024


class FramingError(Exception):
    pass


def encode_frame(payload: bytes):
    if len(payload) > MAX_FRAME_SIZE:
        raise FramingError("payload too large")
    return struct.pack(">I", len(payload)) + payload


def _read_exact(stream, size: int):
    data = b""
    while len(data) < size:
        chunk = stream.read(size - len(data))
        if not chunk:
            raise FramingError("unexpected EOF")
        data += chunk
    return data


def decode_frame(stream):
    size_bytes = _read_exact(stream, 4)
    size = struct.unpack(">I", size_bytes)[0]

    if size > MAX_FRAME_SIZE:
        raise FramingError("frame too large")

    return _read_exact(stream, size)