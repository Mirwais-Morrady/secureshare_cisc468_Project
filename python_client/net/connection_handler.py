"""
Connection handler: performs the full handshake then routes encrypted messages.
"""
from net.framing import decode_frame, FramingError
from protocol.serializer import json_loads_bytes


def handle_connection(conn, addr, identity=None, ctx=None):
    """
    Handle an incoming TCP connection.

    If an identity and context are provided, performs the full server-side
    handshake then routes messages through the MessageRouter.
    Falls back to plain message printing for compatibility testing.

    Args:
        conn: The accepted socket connection
        addr: The remote address tuple
        identity: The local Identity object (for handshake)
        ctx: The runtime context dict
    """
    print(f"[NET] Connection from {addr}")

    if identity is None:
        # Plain mode: just read and print (for testing/compat)
        stream = conn.makefile("rb")
        try:
            while True:
                try:
                    payload = decode_frame(stream)
                except FramingError:
                    break
                msg = json_loads_bytes(payload)
                print(f"[NET] Received: {msg}")
        finally:
            try:
                stream.close()
            except Exception:
                pass
            conn.close()
        return

    try:
        from net.handshake_server import execute_server_handshake
        session, client_hello = execute_server_handshake(conn, identity)
        peer_id = client_hello.get("peer_id", "unknown")
        peer_name = client_hello.get("peer_name", "unknown")
        print(f"[NET] Authenticated: {peer_name} ({peer_id[:16]}...)")

        # Save verified contact
        if ctx is not None and "contacts_store" in ctx:
            contacts = ctx["contacts_store"].load()
            contacts[peer_id] = {
                "peer_name": peer_name,
                "rsa_public_key_der_b64": client_hello.get("rsa_public_key_der_b64"),
            }
            ctx["contacts_store"].save(contacts)

        # Route all subsequent messages through the MessageRouter
        from net.router import MessageRouter
        router = MessageRouter(ctx, conn, session, peer_name, peer_id)
        router.run()

    except Exception as e:
        print(f"[ERROR] Connection from {addr} failed: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass
