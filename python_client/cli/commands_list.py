
from pathlib import Path


def list_files(ctx, arg=""):
    if arg == "downloads":
        dl = Path("data/downloads")
        if not dl.exists():
            print("No downloads folder yet.")
            return
        entries = [p.name for p in dl.iterdir() if p.is_file()]
        if not entries:
            print("Downloads folder is empty.")
        else:
            print("Files in data/downloads/:")
            for name in sorted(entries):
                print(f"  {name}")
        return

    manager = ctx["share_manager"]
    files = manager.list_files()

    if not files:
        print("No files shared")
        return

    for f in files:
        print(f)
