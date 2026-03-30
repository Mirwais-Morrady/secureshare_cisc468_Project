
from pathlib import Path


class ShareManager:

    def __init__(self, shared_dir: Path, shared_vault_store, share_index_store):
        self.shared_dir = shared_dir
        self.shared_vault_store = shared_vault_store
        self.share_index_store = share_index_store
        self.shared_dir.mkdir(parents=True, exist_ok=True)
        self._migrate_plaintext_shares()

    def list_files(self):
        index = self.share_index_store.load()
        return sorted(index.keys())

    def add_file(self, source_path: Path):
        filename = source_path.name
        self.shared_vault_store.store_file(filename, source_path.read_bytes())
        index = self.share_index_store.load()
        index[filename] = {"stored_in": "shared_vault"}
        self.share_index_store.save(index)
        plaintext_path = self.shared_dir / filename
        if plaintext_path.exists():
            plaintext_path.unlink()

    def has_file(self, filename: str):
        index = self.share_index_store.load()
        return filename in index

    def get_file_bytes(self, filename: str) -> bytes:
        if not self.has_file(filename):
            raise FileNotFoundError(filename)
        return self.shared_vault_store.get_file(filename)

    def get_file_size(self, filename: str) -> int:
        return len(self.get_file_bytes(filename))

    def _migrate_plaintext_shares(self):
        index = self.share_index_store.load()
        changed = False
        for path in self.shared_dir.iterdir():
            if not path.is_file():
                continue
            filename = path.name
            self.shared_vault_store.store_file(filename, path.read_bytes())
            index[filename] = {"stored_in": "shared_vault"}
            path.unlink()
            changed = True
        if changed:
            self.share_index_store.save(index)
