import json
from pathlib import Path


class ManifestStore:

    def __init__(self, path: Path):
        self.path = path

    def _load_all(self) -> dict:
        if not self.path.exists():
            return {}
        return json.loads(self.path.read_text())

    def save(self, manifest: dict):
        """Save a single manifest keyed by its file_name."""
        all_manifests = self._load_all()
        filename = manifest.get("file_name")
        if filename:
            all_manifests[filename] = manifest
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(all_manifests, indent=2))

    def get(self, filename: str) -> dict | None:
        """Retrieve the manifest for a specific file, or None if not found."""
        return self._load_all().get(filename)

    def list_all(self) -> dict:
        """Return all stored manifests keyed by filename."""
        return self._load_all()
