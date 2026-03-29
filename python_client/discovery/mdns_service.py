
from zeroconf import Zeroconf, ServiceInfo
import socket

SERVICE_TYPE = "_cisc468share._tcp.local."

def advertise_service(name, port):

    zeroconf = Zeroconf()
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)

    info = ServiceInfo(
        SERVICE_TYPE,
        f"{name}.{SERVICE_TYPE}",
        addresses=[socket.inet_aton(local_ip)],
        port=port,
        properties={},
        server=f"{hostname}.local."
    )

    zeroconf.register_service(info)
    return zeroconf
