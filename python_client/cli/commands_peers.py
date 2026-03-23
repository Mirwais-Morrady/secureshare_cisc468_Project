
def peers(ctx):
    peers = ctx.get("peers", [])
    if not peers:
        print("No peers discovered")
        return

    for p in peers:
        print(f"{p['name']} - {p['address']}")
