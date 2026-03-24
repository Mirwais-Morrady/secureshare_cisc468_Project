"""
Runtime entry point: initialises all subsystems and starts the CLI.
"""
from pathlib import Path
from threading import Thread
import uuid
import socket

from cli.cli import start_cli
from crypto.identity import IdentityManager
from net.discovery_listener import start_discovery
from discovery.mdns_service import advertise_service
from files.share_manager import ShareManager
from net.connection_handler import handle_connection
from net.tcp_server import TCPServer
from storage.config_store import ConfigStore
from storage.contacts_store import ContactsStore
from storage.manifest_store import ManifestStore
from storage.vault_store import VaultStore

def get_available_port():
    """Find an available port"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        s.listen(1)
        port = s.getsockname()[1]
    return port


def build_context(base_dir: Path, identity, vault_password: str = "changeme") -> dict:
    ctx = {}
    ctx["identity"] = identity
    ctx["share_manager"] = ShareManager(base_dir / "data" / "shared")
    ctx["contacts_store"] = ContactsStore(base_dir / "data" / "contacts.json")
    ctx["manifest_store"] = ManifestStore(base_dir / "data" / "manifests.json")
    ctx["vault_store"] = VaultStore(base_dir / "data" / "vault", password=vault_password)
    ctx["peers"] = []
    return ctx


def start_network(ctx, identity, port: int = 40468):
    def handler(conn, addr):
        handle_connection(conn, addr, identity, ctx)

    server = TCPServer("0.0.0.0", port, handler)
    Thread(target=server.start, daemon=True).start()

    ctx["mdns_advertise"] = advertise_service(identity.peer_name, port)
    ctx["mdns_discover"] = start_discovery(ctx)


def run():
    base_dir = Path(__file__).resolve().parent

    config = ConfigStore(base_dir / "data" / "config.json").load()
    peer_name = config.get("peer_name", "secureshare-peer")
    
    # Use unique peer name with UUID
    unique_peer_name = f"{peer_name}-{str(uuid.uuid4())[:8]}"
    
    # Use available port instead of configured one
    port = get_available_port()

    identity_mgr = IdentityManager(base_dir / "data" / "identity")
    identity = identity_mgr.load_or_create_identity(unique_peer_name)

    print(f"[INFO] Identity: {identity.peer_name}")
    print(f"[INFO] Peer ID:  {identity.peer_id}")

    ctx = build_context(base_dir, identity)
    start_network(ctx, identity, port)

    print(f"[INFO] Listening on port {port}")
    start_cli(ctx)
