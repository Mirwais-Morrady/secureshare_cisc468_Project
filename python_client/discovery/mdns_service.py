
from zeroconf import Zeroconf, ServiceInfo

SERVICE_TYPE = "_cisc468share._tcp.local."

def advertise_service(name, port):

    zeroconf = Zeroconf()

    info = ServiceInfo(
        SERVICE_TYPE,
        f"{name}.{SERVICE_TYPE}",
        port=port,
        properties={},
    )

    zeroconf.register_service(info)
    return zeroconf
