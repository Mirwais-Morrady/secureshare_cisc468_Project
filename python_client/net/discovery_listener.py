
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
        peers.append(peer)

        print("Discovered peer:", peer)

def start_discovery(ctx):
    zeroconf = Zeroconf()
    listener = DiscoveryListener(ctx)
    ServiceBrowser(zeroconf, SERVICE_TYPE, listener)
    return zeroconf
