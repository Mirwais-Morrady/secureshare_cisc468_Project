from .commands_list import list_files
from .commands_peers import peers
from .commands_share import share_file
from .commands_connect import connect_peer
from .commands_list_files import list_peer_files

def handle_command(ctx, cmd):
    parts = cmd.strip().split()

    if not parts:
        return

    command = parts[0]

    if command == "help":
        print("Commands:")
        print("  help                         show commands")
        print("  peers                        list discovered peers on the network")
        print("  connect <peer>               connect and authenticate with a peer")
        print("  list-files <peer>            list files shared by a peer (no consent needed)")
        print("  list                         list your own shared files")
        print("  share <file>                 add a file to your shared folder")
        print("  exit                         quit program")
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

    elif command == "connect":
        connect_peer(ctx, cmd)

    elif command == "list-files":
        list_peer_files(ctx, cmd)

    elif command in ("exit", "quit"):
        print("Exiting...")
        raise SystemExit

    else:
        print("Unknown command. Type 'help'")