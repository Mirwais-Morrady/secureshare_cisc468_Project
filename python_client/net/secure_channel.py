
from protocol.serializer import json_dumps_bytes, json_loads_bytes
from net.framing import encode_frame, decode_frame

class SecureChannel:

    def __init__(self, socket):
        self.socket = socket

    def send(self, msg: dict):
        payload = json_dumps_bytes(msg)
        frame = encode_frame(payload)
        self.socket.sendall(frame)

    def receive(self):
        payload = decode_frame(self.socket.makefile("rb"))
        return json_loads_bytes(payload)
