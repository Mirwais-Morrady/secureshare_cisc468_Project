
import json, base64
from pathlib import Path
from crypto.hashing import sha256_file_hex
from protocol.canonical_json import canonical_json_bytes
from crypto.identity import IdentityManager


def build_manifest(peer_id, peer_name, file_path: Path):
    size = file_path.stat().st_size
    sha = sha256_file_hex(file_path)

    manifest = {
        "manifest_version": "1.0",
        "owner_peer_id": peer_id,
        "owner_peer_name": peer_name,
        "file_name": file_path.name,
        "file_size": size,
        "file_sha256_hex": sha,
    }

    return manifest


def sign_manifest(private_key, manifest: dict):
    data = canonical_json_bytes(manifest)
    sig = IdentityManager.sign(private_key, data)
    manifest["signature_b64"] = base64.b64encode(sig).decode()
    return manifest
