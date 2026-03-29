
def peers(ctx):
    peers = ctx.get("peers", [])
    if not peers:
        print("No peers discovered")
        return

    own_name = ctx["identity"].peer_name if "identity" in ctx else None
    for p in peers:
        self_tag = " (self)" if own_name and p["name"].startswith(own_name + ".") else ""
        print(f"{p['name']} - {p['address']}{self_tag}")
