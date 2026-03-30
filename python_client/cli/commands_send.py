from pathlib import Path
from files.transfer_manager import TransferManager


def send_file(ctx, cmd):
    """
    send <peer-name> <file>

    Sends a file to a connected peer. The peer is prompted to accept or
    deny the transfer before any data is sent. If they accept, the file
    is sent in encrypted chunks and the receiver verifies integrity via
    SHA-256.

    The file argument can be:
      - a filename already in your data/shared/ folder  (e.g. project_report.txt)
      - any path on your filesystem                      (e.g. /home/user/doc.pdf)
    """
    args = cmd.strip().split()
    if len(args) < 3:
        print("Usage: send <peer-name> <file>")
        print("  e.g. send java-peer project_report.txt")
        return

    peer_name = args[1]
    file_arg  = " ".join(args[2:])
    filename = Path(file_arg).name
    file_data = None
    file_size = None

    # Resolve the file: check as-is, then inside data/shared/
    file_path = Path(file_arg)
    if file_path.exists():
        file_size = file_path.stat().st_size
    elif ctx["share_manager"].has_file(file_arg):
        try:
            file_data = ctx["share_manager"].get_file_bytes(file_arg)
            file_size = len(file_data)
            filename = file_arg
        except Exception as e:
            print(f"[ERROR] Could not read shared file '{file_arg}': {e}")
            return
    else:
        shared_path = Path("data/shared") / file_arg
        print(f"[ERROR] File not found: '{file_arg}'")
        print(f"  Checked: {file_path}")
        print(f"  Checked: {shared_path}")
        print(f"  Tip: run 'list' to see your shared files.")
        return

    # Auto-connect if needed
    conn = ctx.get("connections", {}).get(peer_name)
    if conn is None:
        print(f"[INFO] Not connected to '{peer_name}'. Connecting first...")
        from cli.commands_connect import connect_peer
        connect_peer(ctx, f"connect {peer_name}")
        conn = ctx.get("connections", {}).get(peer_name)
        if conn is None:
            return

    sock    = conn["sock"]
    stream  = conn["stream"]
    session = conn["session"]

    print(f"[SEND] File      : {filename} ({file_size:,} bytes)")
    print(f"[SEND] Recipient : {peer_name}")
    print(f"[SEND] Sending FILE_REQUEST — waiting for '{peer_name}' to accept or deny ...")
    print(f"       >>> Watch the other terminal for the consent prompt <<<")
    print()

    try:
        mgr = TransferManager(sock, session, peer_name, stream=stream)
        if file_data is not None:
            success = mgr.send_bytes(filename, file_data)
        else:
            success = mgr.send_file(file_path)
    except Exception as e:
        print(f"[ERROR] Transfer failed: {e}")
        ctx["connections"].pop(peer_name, None)
        return

    print()
    if success:
        print(f"[OK] '{filename}' delivered to '{peer_name}' successfully.")
        print(f"     The file was sent over AES-256-GCM encrypted transport.")
        print(f"     SHA-256 integrity hash was verified by the receiver.")
    else:
        print(f"[INFO] Transfer of '{filename}' was denied or cancelled by '{peer_name}'.")
