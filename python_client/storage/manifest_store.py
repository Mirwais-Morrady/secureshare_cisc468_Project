
import json
from pathlib import Path

class ManifestStore:

    def __init__(self, path: Path):
        self.path = path

    def save(self, manifest):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(manifest, indent=2))
