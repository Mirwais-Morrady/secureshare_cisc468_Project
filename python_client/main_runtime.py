"""
Runtime entry point: initialises all subsystems and starts the CLI.
"""
import getpass
import os
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
from storage.share_index_store import ShareIndexStore
from storage.vault_store import VaultStore
from net.consent_manager import ConsentManager
from storage.pending_migration_store import PendingMigrationStore


def resolve_vault_password() -> str:
    password = os.environ.get("SECURESHARE_VAULT_PASSWORD", "").strip()
    if password:
        return password

    while True:
        try:
            password = getpass.getpass("Vault password: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[ERROR] Vault password entry cancelled.")
            raise SystemExit(1)

        if password:
            return password

        print("[ERROR] Vault password cannot be empty.")

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
    shared_vault_store = VaultStore(base_dir / "data" / "shared_vault", password=vault_password)
    ctx["share_manager"] = ShareManager(
        base_dir / "data" / "shared",
        shared_vault_store,
        ShareIndexStore(base_dir / "data" / "share_index.json"),
    )
    ctx["contacts_store"] = ContactsStore(base_dir / "data" / "contacts.json")
    ctx["manifest_store"] = ManifestStore(base_dir / "data" / "manifests.json")
    ctx["vault_store"] = VaultStore(base_dir / "data" / "vault", password=vault_password)
    ctx["shared_vault_store"] = shared_vault_store
    ctx["consent_manager"] = ConsentManager()
    ctx["connections"] = {}
    ctx["inbound_connections"] = {}
    ctx["peers"] = []
    ctx["pending_migration_store"] = PendingMigrationStore(base_dir / "data" / "pending_migrations.json")
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

    vault_password = resolve_vault_password()
    ctx = build_context(base_dir, identity, vault_password=vault_password)
    start_network(ctx, identity, port)

    print(f"[INFO] Listening on port {port}")
    print(f"[INFO] Local vault unlocked.")
    start_cli(ctx)
