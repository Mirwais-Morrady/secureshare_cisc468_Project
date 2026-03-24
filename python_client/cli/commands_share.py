
from pathlib import Path

def share_file(ctx, parts):
    if len(parts) < 2:
        print("Usage: share <file>")
        return

    file_path = Path(parts)

    if not file_path.exists():
        print("File not found")
        return

    shared_dir = ctx["share_manager"].shared_dir
    dest = shared_dir / file_path.name

    dest.write_bytes(file_path.read_bytes())

    print("File shared:", dest.name)
