import json
from pathlib import Path


DEFAULT_CONFIG = {
    "peer_name": "python-peer",
    "host": "0.0.0.0",
    "port": 40468,
    "protocol_version": "1.0",
}


class ConfigStore:
    def __init__(self, path: Path):
        self.path = path

    def load(self) -> dict:
        if not self.path.exists():
            self.save(DEFAULT_CONFIG)
            return dict(DEFAULT_CONFIG)

        data = json.loads(self.path.read_text(encoding="utf-8"))
        merged = dict(DEFAULT_CONFIG)
        merged.update(data)
        return merged

    def save(self, config: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(config, indent=2), encoding="utf-8")
