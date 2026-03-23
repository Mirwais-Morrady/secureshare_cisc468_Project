
class FileReceiver:

    def __init__(self):
        self.buffers = {}

    def receive_chunk(self, msg):
        name = msg["file"]
        idx = msg["index"]
        data = bytes.fromhex(msg["data"])

        if name not in self.buffers:
            self.buffers[name] = {}

        self.buffers[name][idx] = data

    def assemble(self, filename):
        chunks = self.buffers.get(filename, {})
        ordered = [chunks[i] for i in sorted(chunks)]
        return b"".join(ordered)
