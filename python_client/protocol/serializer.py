
import json

def json_dumps_bytes(obj):
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False
    ).encode("utf-8")

def json_loads_bytes(data: bytes):
    return json.loads(data.decode("utf-8"))
