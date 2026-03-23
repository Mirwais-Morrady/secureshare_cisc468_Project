
import json
import hashlib
import os
from base64 import b64encode

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def generate_vectors():
    vectors = []
    samples = [
        b"hello",
        b"secure-share",
        os.urandom(32),
        os.urandom(64)
    ]

    for s in samples:
        vectors.append({
            "input_b64": b64encode(s).decode(),
            "sha256_b64": b64encode(sha256(s)).decode()
        })

    return vectors

def main():
    vectors = generate_vectors()

    out = {
        "description": "Shared SHA256 test vectors for Python/Java interop",
        "vectors": vectors
    }

    with open("interop_vectors.json", "w") as f:
        json.dump(out, f, indent=2)

    print("Generated interop_vectors.json")

if __name__ == "__main__":
    main()
