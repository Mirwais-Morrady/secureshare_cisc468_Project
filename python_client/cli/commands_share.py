from pathlib import Path
from crypto.manifest import build_manifest, sign_manifest


def share_file(ctx, file_arg):
    file_path = Path(file_arg)

    if not file_path.exists():
        print(f"[ERROR] File not found: '{file_arg}'")
        return

    shared_dir = ctx["share_manager"].shared_dir
    dest = shared_dir / file_path.name
    dest.write_bytes(file_path.read_bytes())
    print(f"[OK] File shared: {dest.name}")

    # Sign and store a manifest so peers can verify this file later,
    # even when fetching it indirectly from a third party (Req 5).
    identity = ctx["identity"]
    manifest = build_manifest(identity.peer_id, identity.peer_name, dest)
    signed   = sign_manifest(identity.private_key, manifest)

    if "manifest_store" in ctx:
        ctx["manifest_store"].save(signed)
        print(f"[OK] Manifest signed and stored for '{dest.name}'")
        print(f"     SHA-256 : {signed['file_sha256_hex']}")
        print(f"     Owner   : {identity.peer_name} ({identity.peer_id[:16]}...)")
        print(f"     (Peers can verify this file's integrity even if you go offline)")
