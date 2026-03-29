
from zeroconf import Zeroconf, ServiceBrowser

SERVICE_TYPE = "_cisc468share._tcp.local."

class DiscoveryListener:

    def __init__(self, ctx):
        self.ctx = ctx

    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        if not info:
            return

        address = ".".join(map(str, info.addresses[0]))
        peer = {
            "name": name,
            "address": address,
            "port": info.port
        }

        peers = self.ctx.setdefault("peers", [])
        # Replace any existing entry with the same name so stale ports don't linger
        peers[:] = [p for p in peers if p["name"] != name]
        peers.append(peer)

        print("Discovered peer:", peer)

    def remove_service(self, zeroconf, type, name):
        peers = self.ctx.get("peers", [])
        peers[:] = [p for p in peers if p["name"] != name]

    def update_service(self, zeroconf, service_type, name):
        # Re-resolve so updated port/address is picked up
        self.add_service(zeroconf, service_type, name)

def start_discovery(ctx):
    zeroconf = Zeroconf()
    listener = DiscoveryListener(ctx)
    ServiceBrowser(zeroconf, SERVICE_TYPE, listener)
    return zeroconf
