import base64
import hashlib
from pathlib import Path

from crypto.identity import IdentityManager
from crypto.session import encrypt, decrypt
from net.file_receiver import FileReceiver
from net.framing import encode_frame, decode_frame
from protocol.canonical_json import canonical_json_bytes
from protocol.message_types import (
    GET_FILE_REQUEST,
    FILE_REQUEST_ACCEPT, FILE_REQUEST_DENY,
    FILE_CHUNK, FILE_TRANSFER_COMPLETE, ERROR,
)
from protocol.serializer import json_dumps_bytes, json_loads_bytes


def _send(sock, session, msg):
    plaintext = json_dumps_bytes(msg)
    envelope  = encrypt(session, msg.get("type", "UNKNOWN"), plaintext)
    sock.sendall(encode_frame(json_dumps_bytes(envelope)))


def _recv(stream, session):
    raw      = decode_frame(stream)
    envelope = json_loads_bytes(raw)
    return json_loads_bytes(decrypt(session, envelope))


def _verify_manifest_signature(manifest: dict, public_key) -> bool:
    """
    Verify the RSA-PSS signature on a manifest using the original
    owner's public key.  Returns True if valid, raises on failure.
    """
    sig   = base64.b64decode(manifest["signature_b64"])
    body  = {k: v for k, v in manifest.items() if k != "signature_b64"}
    IdentityManager.verify(public_key, canonical_json_bytes(body), sig)
    return True


def fetch_file(ctx, cmd):
    """
    fetch <peer-name> <filename>

    Fetches a file from <peer-name> when the original owner (Peer A) may
    be offline.  Peer B (us) already has Peer A's signed manifest stored
    locally from a previous listing.  After downloading from <peer-name>
    (Peer C), the file is verified against the manifest:

      1. SHA-256 of received bytes must match the manifest's hash.
      2. The manifest's RSA-PSS signature must verify with the original
         owner's public key (from contacts or our own identity).

    This proves the file was not tampered with by the redistributing peer.
    """
    args = cmd.strip().split()
    if len(args) < 3:
        print("Usage: fetch <peer-name> <filename>")
        print("  e.g. fetch java-peer project_report.txt")
        print()
        print("  Use this when the original owner is offline. You must have")
        print("  the owner's signed manifest stored (run 'share <file>' first,")
        print("  or receive a manifest from the original owner).")
        return

    peer_name = args[1]
    filename  = " ".join(args[2:])

    # ------------------------------------------------------------------ #
    # Step 1: look up the stored manifest for this file                   #
    # ------------------------------------------------------------------ #
    manifest_store = ctx.get("manifest_store")
    manifest = manifest_store.get(filename) if manifest_store else None

    if manifest is None:
        print(f"[ERROR] No signed manifest found for '{filename}'.")
        print(f"  The original owner must have shared this file with you first")
        print(f"  (which creates the manifest).  Run 'share {filename}' on the")
        print(f"  original owner's client, or list their files to receive it.")
        return

    owner_peer_id   = manifest.get("owner_peer_id")
    owner_peer_name = manifest.get("owner_peer_name")
    expected_sha256 = manifest.get("file_sha256_hex")

    print(f"[FETCH] File            : {filename}")
    print(f"[FETCH] Fetching from   : {peer_name}  (the redistributor, Peer C)")
    print(f"[FETCH] Original owner  : {owner_peer_name} ({owner_peer_id[:16]}...)")
    print(f"[FETCH] Expected SHA-256: {expected_sha256[:32]}...")
    print(f"[FETCH] Owner may be offline — verifying via signed manifest")
    print()

    # ------------------------------------------------------------------ #
    # Step 2: resolve the owner's public key for signature verification   #
    # ------------------------------------------------------------------ #
    # Check contacts first, then fall back to our own identity
    # (when we are the original owner demonstrating the flow).
    owner_pub_key = None
    contacts = ctx["contacts_store"].load() if "contacts_store" in ctx else {}

    if owner_peer_id in contacts:
        from cryptography.hazmat.primitives import serialization
        raw_der = base64.b64decode(contacts[owner_peer_id]["rsa_public_key_der_b64"])
        owner_pub_key = serialization.load_der_public_key(raw_der)
        print(f"[INFO] Owner's public key found in contacts.")
    elif ctx["identity"].peer_id == owner_peer_id:
        owner_pub_key = ctx["identity"].public_key
        print(f"[INFO] We are the original owner — using our own public key.")
    else:
        print(f"[WARN] Owner's public key not in contacts — manifest signature")
        print(f"       cannot be verified.  SHA-256 integrity will still be checked.")

    # ------------------------------------------------------------------ #
    # Step 3: connect to the redistributor (Peer C) and request the file  #
    # ------------------------------------------------------------------ #
    conn = ctx.get("connections", {}).get(peer_name)
    if conn is None:
        print(f"[INFO] Not connected to '{peer_name}'. Connecting first...")
        from cli.commands_connect import connect_peer
        connect_peer(ctx, f"connect {peer_name}")
        conn = ctx.get("connections", {}).get(peer_name)
        if conn is None:
            return

    sock    = conn["sock"]
    stream  = conn["stream"]
    session = conn["session"]

    print(f"[FETCH] Requesting '{filename}' from '{peer_name}' ...")
    print(f"        >>> Watch the other terminal for the consent prompt <<<")
    print()

    try:
        _send(sock, session, {"type": GET_FILE_REQUEST, "file": filename})

        response = _recv(stream, session)
        resp_type = response.get("type")

        if resp_type == FILE_REQUEST_DENY:
            print(f"[INFO] '{peer_name}' denied the request: {response.get('reason')}")
            return
        if resp_type == ERROR:
            print(f"[ERROR] {peer_name}: {response.get('message')}")
            return
        if resp_type != FILE_REQUEST_ACCEPT:
            print(f"[ERROR] Unexpected response: {resp_type}")
            return

        print(f"[INFO] '{peer_name}' accepted — receiving file ...")

        receiver = FileReceiver()
        while True:
            msg = _recv(stream, session)
            t   = msg.get("type")

            if t == FILE_CHUNK:
                receiver.receive_chunk(msg)

            elif t == FILE_TRANSFER_COMPLETE:
                data = receiver.assemble(filename)
                actual_sha256 = hashlib.sha256(data).hexdigest()

                print()
                print(f"[VERIFY] Received {len(data):,} bytes from '{peer_name}' (Peer C).")
                print()

                # -- SHA-256 check --
                if actual_sha256 == expected_sha256:
                    print(f"[VERIFY] SHA-256 check : PASSED")
                    print(f"         Expected : {expected_sha256}")
                    print(f"         Actual   : {actual_sha256}")
                else:
                    print(f"[SECURITY ERROR] SHA-256 check FAILED!")
                    print(f"  Expected : {expected_sha256}")
                    print(f"  Actual   : {actual_sha256}")
                    print(f"  '{peer_name}' served a TAMPERED file. Discarding.")
                    return

                # -- Manifest signature check --
                if owner_pub_key is not None:
                    try:
                        _verify_manifest_signature(manifest, owner_pub_key)
                        print(f"[VERIFY] Manifest signature : PASSED")
                        print(f"         The manifest was signed by {owner_peer_name}.")
                        print(f"         Even though {owner_peer_name} may be offline,")
                        print(f"         the file is provably the same one they offered.")
                    except Exception as e:
                        print(f"[SECURITY ERROR] Manifest signature FAILED: {e}")
                        print(f"  The manifest may be forged. Discarding.")
                        return

                # -- Save --
                downloads = Path("data/downloads")
                downloads.mkdir(parents=True, exist_ok=True)
                out_path = downloads / filename
                out_path.write_bytes(data)

                print()
                print(f"[OK] '{filename}' fetched, verified, and saved.")
                print(f"  Saved to  : {out_path}")
                print(f"  Transport : AES-256-GCM encrypted end-to-end")
                return

            elif t == ERROR:
                print(f"[ERROR] {peer_name}: {msg.get('message')}")
                return
            else:
                print(f"[ERROR] Unexpected message: {t}")
                return

    except Exception as e:
        print(f"[ERROR] Fetch failed: {e}")
        ctx.get("connections", {}).pop(peer_name, None)
