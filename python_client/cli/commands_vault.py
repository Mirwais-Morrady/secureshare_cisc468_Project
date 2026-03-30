from pathlib import Path


def _print_usage():
    print("Usage:")
    print("  vault list")
    print("  vault get <file>")
    print("  vault delete <file>")


def vault_command(ctx, cmd):
    vault = ctx.get("vault_store")
    if vault is None:
        print("[ERROR] Vault is not available.")
        return

    parts = cmd.strip().split(maxsplit=2)
    if len(parts) < 2:
        _print_usage()
        return

    action = parts[1]

    if action == "list":
        files = vault.list_files()
        if not files:
            print("Vault is empty.")
            return
        print("Encrypted vault files:")
        for filename in files:
            print(f"  {filename}")
        return

    if len(parts) < 3:
        _print_usage()
        return

    filename = parts[2]

    if action == "get":
        try:
            data = vault.get_file(filename)
        except FileNotFoundError as e:
            print(f"[ERROR] {e}")
            return
        except Exception as e:
            print(f"[SECURITY ERROR] Could not decrypt '{filename}': {e}")
            return

        downloads = Path("data/downloads")
        downloads.mkdir(parents=True, exist_ok=True)
        out_path = downloads / filename
        out_path.write_bytes(data)
        print(f"[OK] Exported '{filename}' from vault to {out_path}")
        return

    if action == "delete":
        vault.delete_file(filename)
        print(f"[OK] Deleted '{filename}' from the encrypted vault.")
        return

    _print_usage()