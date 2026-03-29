import json
from pathlib import Path

class PendingMigrationStore:
    def __init__(self, path: Path):
        self.path = path

    def load(self):
        if not self.path.exists():
            return {"notices": []}
        data = json.loads(self.path.read_text())
        if "notices" not in data or not isinstance(data["notices"], list):
            return {"notices": []}
        return data

    def save(self, data):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, indent=2))

    def queue_notice(self, notice_id: str, message: dict, pending_peer_ids: list[str]):
        data = self.load()
        notices = [n for n in data["notices"] if n.get("id") != notice_id]
        notices.append({
            "id": notice_id,
            "message": message,
            "pending_peer_ids": sorted(set(pending_peer_ids)),
        })
        data["notices"] = notices
        self.save(data)

    def get_pending_for_peer(self, peer_id: str):
        return [
            notice for notice in self.load()["notices"]
            if peer_id in notice.get("pending_peer_ids", [])
        ]

    def mark_delivered(self, notice_id: str, peer_id: str):
        data = self.load()
        updated = []
        for notice in data["notices"]:
            if notice.get("id") == notice_id:
                remaining = [pid for pid in notice.get("pending_peer_ids", []) if pid != peer_id]
                if remaining:
                    notice = dict(notice)
                    notice["pending_peer_ids"] = remaining
                    updated.append(notice)
            else:
                updated.append(notice)
        data["notices"] = updated
        self.save(data)