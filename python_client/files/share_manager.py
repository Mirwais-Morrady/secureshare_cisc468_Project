
from pathlib import Path

class ShareManager:

    def __init__(self, shared_dir: Path):
        self.shared_dir = shared_dir
        self.shared_dir.mkdir(parents=True, exist_ok=True)

    def list_files(self):
        return [p.name for p in self.shared_dir.iterdir() if p.is_file()]
