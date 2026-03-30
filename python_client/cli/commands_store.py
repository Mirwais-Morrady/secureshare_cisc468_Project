from pathlib import Path


def store_file(ctx, cmd):
    args = cmd.strip().split(maxsplit=1)
    if len(args) < 2:
        print("Usage: store <file_path>")
        return

    source = Path(args[1]).expanduser()
    if not source.exists() or not source.is_file():
        # Try data/downloads/ as a fallback (common location for received files)
        fallback = Path("data/downloads") / args[1]
        if fallback.exists() and fallback.is_file():
            source = fallback
        else:
            print(f"[ERROR] File not found: '{args[1]}'")
            print(f"       Looked in: ./{args[1]} and data/downloads/{args[1]}")
            return

    vault = ctx.get("vault_store")
    if vault is None:
        print("[ERROR] Vault is not available.")
        return

    vault.store_file(source.name, source.read_bytes())
    print(f"[OK] Stored '{source.name}' in the encrypted vault.")
    print("     The plaintext file remains at its original location unless you remove it.")