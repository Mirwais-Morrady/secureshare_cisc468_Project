
import json
from pathlib import Path

class ShareIndexStore:

    def __init__(self, path: Path):
        self.path = path

    def load(self):
        if not self.path.exists():
            return {}
        return json.loads(self.path.read_text())

    def save(self, data):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, indent=2))
