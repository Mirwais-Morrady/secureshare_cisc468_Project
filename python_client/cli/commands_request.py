import hashlib
from pathlib import Path

from crypto.session import encrypt, decrypt
from net.file_receiver import FileReceiver
from net.framing import encode_frame, decode_frame
from protocol.message_types import (
    GET_FILE_REQUEST,
    FILE_REQUEST_ACCEPT, FILE_REQUEST_DENY,
    FILE_CHUNK, FILE_TRANSFER_COMPLETE, ERROR,
)
from protocol.serializer import json_dumps_bytes, json_loads_bytes


def _send(sock, session, msg):
    msg_type = msg.get("type", "UNKNOWN")
    plaintext = json_dumps_bytes(msg)
    envelope = encrypt(session, msg_type, plaintext)
    sock.sendall(encode_frame(json_dumps_bytes(envelope)))


def _recv(stream, session):
    raw = decode_frame(stream)
    envelope = json_loads_bytes(raw)
    plaintext = decrypt(session, envelope)
    return json_loads_bytes(plaintext)


def request_file(ctx, cmd):
    """
    request <peer-name> <filename>

    Asks a peer to send us a specific file. The peer is shown a consent
    prompt and must accept before any data is transferred. If accepted,
    the file is received in encrypted chunks, the SHA-256 is verified,
    and the file is saved to data/downloads/.
    """
    args = cmd.strip().split()
    if len(args) < 3:
        print("Usage: request <peer-name> <filename>")
        print("  e.g. request java-peer java_readme.txt")
        return

    peer_name = args[1]
    filename  = " ".join(args[2:])

    # Auto-connect if needed
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

    print(f"[REQUEST] File     : {filename}")
    print(f"[REQUEST] From     : {peer_name}")
    print(f"[REQUEST] Sending GET_FILE_REQUEST — waiting for '{peer_name}' to accept or deny ...")
    print(f"          >>> Watch the other terminal for the consent prompt <<<")
    print()

    try:
        _send(sock, session, {"type": GET_FILE_REQUEST, "file": filename})

        # First response: accept or deny
        response = _recv(stream, session)
        resp_type = response.get("type")

        if resp_type == FILE_REQUEST_DENY:
            reason = response.get("reason", "no reason given")
            print(f"[INFO] '{peer_name}' denied the request: {reason}")
            return

        if resp_type == ERROR:
            print(f"[ERROR] {peer_name} reported an error: {response.get('message')}")
            return

        if resp_type != FILE_REQUEST_ACCEPT:
            print(f"[ERROR] Unexpected response: {resp_type}")
            return

        print(f"[INFO] '{peer_name}' accepted — receiving file ...")

        # Receive chunks until FILE_TRANSFER_COMPLETE
        receiver = FileReceiver()
        while True:
            msg = _recv(stream, session)
            msg_type = msg.get("type")

            if msg_type == FILE_CHUNK:
                receiver.receive_chunk(msg)

            elif msg_type == FILE_TRANSFER_COMPLETE:
                expected_sha256 = msg.get("sha256_hex")
                data = receiver.assemble(filename)

                # Integrity verification
                actual_sha256 = hashlib.sha256(data).hexdigest()
                if expected_sha256 and actual_sha256 != expected_sha256:
                    print(f"[SECURITY ERROR] Integrity check FAILED for '{filename}'!")
                    print(f"  Expected SHA-256 : {expected_sha256}")
                    print(f"  Actual SHA-256   : {actual_sha256}")
                    print(f"  The file may have been tampered with in transit. Discarding.")
                    return

                # Save to downloads/
                downloads = Path("data/downloads")
                downloads.mkdir(parents=True, exist_ok=True)
                out_path = downloads / filename
                out_path.write_bytes(data)

                print(f"[OK] '{filename}' received and saved.")
                print(f"  Size      : {len(data):,} bytes")
                print(f"  SHA-256   : {actual_sha256}")
                print(f"  Integrity : OK — hash matches what '{peer_name}' sent")
                print(f"  Saved to  : {out_path}")
                print(f"  Transport : AES-256-GCM encrypted end-to-end")
                return

            elif msg_type == ERROR:
                print(f"[ERROR] {peer_name} reported an error: {msg.get('message')}")
                return

            else:
                print(f"[ERROR] Unexpected message during transfer: {msg_type}")
                return

    except Exception as e:
        print(f"[ERROR] Transfer failed: {e}")
        ctx.get("connections", {}).pop(peer_name, None)
