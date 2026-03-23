from net.file_transfer import stream_file_chunks, build_transfer_complete
from net.framing import encode_frame
from protocol.serializer import json_dumps_bytes


class FileSender:
    def __init__(self, socket):
        self.socket = socket

    def send_file(self, filename, data):
        for msg in stream_file_chunks(filename, data):
            payload = json_dumps_bytes(msg)
            self.socket.sendall(encode_frame(payload))

        done = build_transfer_complete(filename)
        self.socket.sendall(encode_frame(json_dumps_bytes(done)))
