import select
import sys

from cli.commands import handle_command


def _handle_consent(context):
    """
    Called from the main thread when a consent request is pending.
    Prints the prompt and reads the response — safe because we are on
    the main thread and the background thread is blocked waiting.
    """
    consent_mgr = context.get("consent_manager")
    peer_name, filename, filesize = consent_mgr.pop_pending()

    print(f"\n[INCOMING FILE REQUEST]")
    print(f"  Peer : {peer_name}")
    print(f"  File : {filename}")
    print(f"  Size : {filesize:,} bytes")
    try:
        response = input("  Accept? [y/N]: ").strip().lower()
        accepted = response in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        accepted = False

    consent_mgr.respond(accepted)

    if accepted:
        print(f"[INFO] Accepted — '{filename}' will be received from {peer_name}.")
    else:
        print(f"[INFO] Denied — rejected '{filename}' from {peer_name}.")


def start_cli(context):
    consent_mgr = context.get("consent_manager")
    print("SecureShare CLI started. Type 'help' for commands.")

    while True:
        # Check for a pending consent before printing the prompt
        if consent_mgr and consent_mgr.is_pending():
            _handle_consent(context)
            continue

        sys.stdout.write("secure-share> ")
        sys.stdout.flush()

        # Use select with a short timeout so we can check for incoming
        # consent requests even while waiting for the user to type.
        cmd = None
        while cmd is None:
            try:
                ready, _, _ = select.select([sys.stdin], [], [], 0.3)
            except (ValueError, OSError):
                return  # stdin closed

            if ready:
                line = sys.stdin.readline()
                if not line:   # EOF / Ctrl-D
                    print()
                    return
                cmd = line.strip()
            elif consent_mgr and consent_mgr.is_pending():
                # Consent arrived while we were waiting — newline to tidy
                # the terminal, then handle it, then re-print the prompt.
                print()
                _handle_consent(context)
                sys.stdout.write("secure-share> ")
                sys.stdout.flush()

        if not cmd:
            continue
        if cmd in ("exit", "quit"):
            print("Exiting...")
            break

        try:
            handle_command(context, cmd)
        except KeyboardInterrupt:
            print("\nExiting...")
            break
