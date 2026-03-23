
CHUNK_SIZE = 65536

def chunk_bytes(data: bytes):
    for i in range(0, len(data), CHUNK_SIZE):
        yield data[i:i+CHUNK_SIZE]
