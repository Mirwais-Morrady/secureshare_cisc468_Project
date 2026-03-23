
def list_files(ctx):
    manager = ctx["share_manager"]
    files = manager.list_files()

    if not files:
        print("No files shared")
        return

    for f in files:
        print(f)
