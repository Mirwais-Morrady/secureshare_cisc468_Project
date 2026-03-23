
def get_file(ctx, parts):
    if len(parts) < 2:
        print("Usage: get <file>")
        return

    filename = parts[1]
    print(f"Requesting file: {filename}")
