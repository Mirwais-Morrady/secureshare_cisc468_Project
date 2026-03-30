from pathlib import Path


def store_file(ctx, cmd):
    args = cmd.strip().split(maxsplit=1)
    if len(args) < 2:
        print("Usage: store <file_path>")
        return

    source = Path(args[1]).expanduser()
    if not source.exists() or not source.is_file():
        print(f"[ERROR] File not found: '{args[1]}'")
        return

    vault = ctx.get("vault_store")
    if vault is None:
        print("[ERROR] Vault is not available.")
        return

    vault.store_file(source.name, source.read_bytes())
    print(f"[OK] Stored '{source.name}' in the encrypted vault.")
    print("     The plaintext file remains at its original location unless you remove it.")