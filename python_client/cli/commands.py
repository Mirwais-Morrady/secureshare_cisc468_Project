from .commands_list import list_files
from .commands_peers import peers
from .commands_share import share_file
from .commands_connect import connect_peer
from .commands_list_files import list_peer_files
from .commands_send import send_file
from .commands_request import request_file
from .commands_fetch import fetch_file
from .commands_rotate_key import rotate_key
from .commands_store import store_file
from .commands_vault import vault_command

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
        print("  send <peer> <file>           send a file to a peer (they must consent)")
        print("  request <peer> <file>        request a file from a peer (they must consent)")
        print("  fetch <peer> <file>          fetch from a redistributor and verify against signed manifest")
        print("  list                         list your own shared files")
        print("  share <file>                 add a file to your shared folder")
        print("  store <file>                 store a local file in the encrypted vault")
        print("  vault list                   list files stored in the encrypted vault")
        print("  vault get <file>             export a vault file to data/downloads/")
        print("  vault delete <file>          delete a file from the encrypted vault")
        print("  rotate-key                   generate new RSA key pair and notify connected peers")
        print("  exit                         quit program")
    elif command == "list":
        list_files(ctx)

    elif command == "share":
        if len(parts) < 2:
            print("Usage: share <file_path>")
            return

        file_path = " ".join(parts[1:])
        share_file(ctx, file_path)

    elif command == "store":
        store_file(ctx, cmd)

    elif command == "vault":
        vault_command(ctx, cmd)

    elif command == "peers":
        peers(ctx)

    elif command == "connect":
        connect_peer(ctx, cmd)

    elif command == "list-files":
        list_peer_files(ctx, cmd)

    elif command == "send":
        send_file(ctx, cmd)

    elif command == "request":
        request_file(ctx, cmd)

    elif command == "fetch":
        fetch_file(ctx, cmd)

    elif command == "rotate-key":
        rotate_key(ctx, cmd)

    elif command in ("exit", "quit"):
        print("Exiting...")
        raise SystemExit

    else:
        print("Unknown command. Type 'help'")