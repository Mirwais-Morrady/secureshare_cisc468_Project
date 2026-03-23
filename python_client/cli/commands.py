def handle_command(ctx, cmd):
    parts = cmd.strip().split()

    if not parts:
        return

    command = parts[0]

    if command == "help":
        print("Commands:")
        print("  help        show commands")
        print("  peers       list discovered peers")
        print("  exit        quit program")

    elif command == "peers":
        peers = ctx.get("peers", [])

        if not peers:
            print("No peers discovered.")
            return

        print("Discovered peers:")
        for p in peers:
            print(f" - {p}")

    elif command in ("exit", "quit"):
        print("Exiting...")
        raise SystemExit

    else:
        print("Unknown command. Type 'help'")