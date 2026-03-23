from pathlib import Path

from crypto.identity import IdentityManager
from storage.config_store import ConfigStore


def ensure_runtime_dirs(base_dir: Path) -> None:
    dirs = [
        base_dir / "data" / "identity",
        base_dir / "data" / "contacts",
        base_dir / "data" / "vault" / "files",
        base_dir / "data" / "manifests",
        base_dir / "data" / "shared",
        base_dir / "data" / "downloads" / "temp",
        base_dir / "data" / "logs",
        base_dir / "data" / "config",
    ]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)


def main() -> None:
    base_dir = Path(__file__).resolve().parent
    ensure_runtime_dirs(base_dir)

    config_store = ConfigStore(base_dir / "data" / "config" / "config.json")
    config = config_store.load()

    identity_dir = base_dir / "data" / "identity"
    identity_manager = IdentityManager(identity_dir)
    identity = identity_manager.load_or_create_identity(
        peer_name=config.get("peer_name", "python-peer")
    )

    print("Secure Share Python Client")
    print(f"Peer name: {identity.peer_name}")
    print(f"Peer ID:   {identity.peer_id}")
    print(f"Fingerp.:  {identity.fingerprint_hex}")
    print("Bootstrap complete.")


if __name__ == "__main__":
    main()
