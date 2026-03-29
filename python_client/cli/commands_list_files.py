from crypto.session import encrypt, decrypt
from net.framing import encode_frame, decode_frame
from protocol.message_types import LIST_FILES_REQUEST, LIST_FILES_RESPONSE
from protocol.serializer import json_dumps_bytes, json_loads_bytes


def _send(sock, session, msg):
    msg_type = msg.get("type", "UNKNOWN")
    plaintext = json_dumps_bytes(msg)
    envelope = encrypt(session, msg_type, plaintext)
    sock.sendall(encode_frame(json_dumps_bytes(envelope)))


def _recv(sock, session):
    stream = sock.makefile("rb")
    raw = decode_frame(stream)
    envelope = json_loads_bytes(raw)
    plaintext = decrypt(session, envelope)
    return json_loads_bytes(plaintext)


def list_peer_files(ctx, cmd):
    """
    list-files <peer-name>

    Sends a LIST_FILES_REQUEST to the named peer over the established
    encrypted session and prints their shared file list.
    No consent is required from the remote peer.
    """
    args = cmd.strip().split()
    if len(args) < 2:
        print("Usage: list-files <peer-name>")
        print("  e.g. list-files java-peer")
        return

    peer_name = args[1]

    # Auto-connect if not already connected
    conn = ctx.get("connections", {}).get(peer_name)
    if conn is None:
        print(f"[INFO] Not connected to '{peer_name}'. Connecting first...")
        from cli.commands_connect import connect_peer
        connect_peer(ctx, f"connect {peer_name}")
        conn = ctx.get("connections", {}).get(peer_name)
        if conn is None:
            return  # connect_peer already printed the error

    sock    = conn["sock"]
    session = conn["session"]

    print(f"[LIST-FILES] Requesting file list from '{peer_name}' ...")
    print(f"             (No consent required for this operation)")
    print()

    try:
        _send(sock, session, {"type": LIST_FILES_REQUEST})
        response = _recv(sock, session)
    except Exception as e:
        print(f"[ERROR] Lost connection to '{peer_name}': {e}")
        ctx["connections"].pop(peer_name, None)
        return

    if response.get("type") != LIST_FILES_RESPONSE:
        print(f"[ERROR] Unexpected response: {response.get('type')}")
        return

    files = response.get("files", [])

    if not files:
        print(f"  {peer_name} has no files available for sharing.")
    else:
        print(f"  Files shared by '{peer_name}' ({len(files)} total):")
        for f in files:
            print(f"    - {f}")

    print()
    print(f"[OK] File list received. No consent was needed — this is a read-only listing.")
