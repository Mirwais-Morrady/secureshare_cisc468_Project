
from cli.commands import handle_command

def start_cli(context):
    print("SecureShare CLI started. Type 'help' for commands.")

    while True:
        try:
            cmd = input("secure-share> ").strip()
            if not cmd:
                continue
            if cmd in ("exit", "quit"):
                print("Exiting...")
                break

            handle_command(context, cmd)

        except KeyboardInterrupt:
            print("\nExiting...")
            break
