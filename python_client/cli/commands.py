from .commands_list import list_files
from .commands_peers import peers
from .commands_share import share_file

def handle_command(ctx, cmd):
    parts = cmd.strip().split()

    if not parts:
        return

    command = parts[0]

    if command == "help":
        print("Commands:")
        print("  help          show commands")
        print("  peers         list discovered peers")
        print("  exit          quit program")
        print("  share <file>  share a file")
        print("  list          list shared files")
    elif command == "list":
        list_files(ctx)

    elif command == "share":
        if len(parts) < 2:
            print("Usage: share <file_path>")
            return

        file_path = " ".join(parts[1:])
        share_file(ctx, file_path)

    elif command == "peers":
        peers(ctx)

    elif command in ("exit", "quit"):
        print("Exiting...")
        raise SystemExit

    else:
        print("Unknown command. Type 'help'")