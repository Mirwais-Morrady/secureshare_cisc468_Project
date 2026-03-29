import socket as _socket
from net.handshake_client import execute_client_handshake
from net.tcp_client import connect
from crypto.key_migration import flush_pending_migrations


def _find_peer(ctx, name):
    """
    Find a peer in ctx["peers"] by short name.
    Matches if the peer's mDNS name starts with the given name.
    e.g. "java-peer" matches "java-peer._cisc468share._tcp.local."
    """
    for peer in ctx.get("peers", []):
        full_name = peer["name"]
        short_name = full_name.split(".")[0]
        if short_name == name or full_name == name:
            return peer
    return None


def connect_peer(ctx, parts):
    """
    connect <peer-name>

    Opens a TCP connection to the named peer, performs the full mutual-
    authentication handshake (RSA-PSS + ephemeral DH), and prints:
      - The peer's verified fingerprint
      - The negotiated session ID
      - Confirmation that both sides authenticated each other

    The live session is stored in ctx["connections"][peer_name] so that
    subsequent commands (list-files, send, request) can reuse it.
    """
    args = parts.strip().split()
    if len(args) < 2:
        print("Usage: connect <peer-name>")
        print("  e.g. connect java-peer")
        return

    peer_name = args[1]
    peer = _find_peer(ctx, peer_name)

    if peer is None:
        discovered = [p["name"].split(".")[0] for p in ctx.get("peers", [])]
        if discovered:
            print(f"[ERROR] Peer '{peer_name}' not found.")
            print(f"  Known peers: {', '.join(discovered)}")
        else:
            print(f"[ERROR] No peers discovered yet. Try running 'peers' first.")
        return

    address = peer["address"]
    port    = peer["port"]
    identity = ctx["identity"]

    print(f"[CONNECT] Connecting to {peer_name} at {address}:{port} ...")

    try:
        sock = connect(address, port)
    except ConnectionRefusedError:
        print(f"[ERROR] Connection refused — is {peer_name} still running?")
        return
    except OSError as e:
        print(f"[ERROR] Could not connect: {e}")
        return

    print(f"[CONNECT] TCP connection established.")
    print(f"[CONNECT] Starting mutual authentication handshake ...")
    print(f"          Our identity  : {identity.peer_name}")
    print(f"          Our fingerprint: {identity.peer_id[:32]}...")

    try:
        session, server_hello = execute_client_handshake(sock, identity)
    except Exception as e:
        print(f"[ERROR] Handshake failed: {e}")
        print(f"  The peer's identity could not be verified. Connection closed.")
        sock.close()
        return

    remote_peer_id   = server_hello.get("peer_id", "unknown")
    remote_peer_name = server_hello.get("peer_name", peer_name)

    print()
    print(f"[AUTH] Handshake complete.")
    print(f"  Peer name       : {remote_peer_name}")
    print(f"  Peer fingerprint: {remote_peer_id}")
    print(f"  Session ID      : {session.session_id}")
    print()
    print(f"[AUTH] Mutual authentication successful.")
    print(f"  - We verified {remote_peer_name}'s RSA-PSS signature.")
    print(f"  - {remote_peer_name} verified our RSA-PSS signature.")
    print(f"  - Session keys derived via ephemeral Diffie-Hellman (new keys, never stored).")
    print(f"  - All further communication is AES-256-GCM encrypted.")

    # One shared stream per connection — prevents multiple makefile() buffers
    # from stealing each other's bytes off the same socket.
    stream = sock.makefile("rb")

    # Store the active connection for reuse by other commands
    if "connections" not in ctx:
        ctx["connections"] = {}
    ctx["connections"][peer_name] = {
        "sock":      sock,
        "stream":    stream,
        "session":   session,
        "peer_id":   remote_peer_id,
        "peer_name": remote_peer_name,
        "address":   address,
        "port":      port,
    }
    try:
        flush_pending_migrations(ctx, remote_peer_id, sock, session, peer_name=peer_name)
    except Exception as e:
        print(f"[WARN] Could not deliver pending KEY_MIGRATION to '{peer_name}': {e}")

    print()
    print(f"[OK] Connected to '{peer_name}'. You can now run:")
    print(f"  list-files {peer_name}     — see their shared files")
    print(f"  send {peer_name} <file>    — send a file (they will be prompted)")
    print(f"  request {peer_name} <file> — request a file from them")
