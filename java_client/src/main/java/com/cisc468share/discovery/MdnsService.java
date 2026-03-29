package com.cisc468share.discovery;

import javax.jmdns.JmDNS;
import javax.jmdns.ServiceInfo;
import java.io.IOException;
import java.net.InetAddress;
import java.util.List;
import java.util.ArrayList;
import java.util.Collections;
import javax.jmdns.ServiceEvent;
import javax.jmdns.ServiceListener;

public class MdnsService {
    public static class PeerInfo {
        public final String name;
        public final String address;
        public final int port;

        public PeerInfo(String name, String address, int port) {
            this.name = name;
            this.address = address;
            this.port = port;
        }

        @Override
        public String toString() {
            return String.format("%s (%s:%d)", name, address, port);
        }
    }

    private JmDNS jmdns;
    private final List<PeerInfo> discoveredPeers = Collections.synchronizedList(new ArrayList<>());

    public void start(String name, int port) throws IOException {

        jmdns = JmDNS.create(InetAddress.getLocalHost());

        ServiceInfo serviceInfo = ServiceInfo.create(
                "_cisc468share._tcp.local.",
                name,
                port,
                "Secure Share peer"
        );

        jmdns.registerService(serviceInfo);

        jmdns.addServiceListener("_cisc468share._tcp.local.", new ServiceListener() {
            @Override
            public void serviceAdded(ServiceEvent event) {
                // Request service info to trigger serviceResolved
                jmdns.requestServiceInfo(event.getType(), event.getName(), 1);
            }

            @Override
            public void serviceRemoved(ServiceEvent event) {
                discoveredPeers.removeIf(p -> p.name.equals(event.getName()));
            }

            @Override
            public void serviceResolved(ServiceEvent event) {
                ServiceInfo info = event.getInfo();
                String name = event.getName();
                String address = info.getInetAddresses().length > 0
                        ? info.getInetAddresses()[0].getHostAddress() : "unknown";
                int port = info.getPort();
                PeerInfo peer = new PeerInfo(name, address, port);
                // Only print if this is a genuinely new or changed entry
                boolean isNew = discoveredPeers.stream().noneMatch(
                        p -> p.name.equals(name) && p.address.equals(address) && p.port == port);
                discoveredPeers.removeIf(p -> p.name.equals(name));
                discoveredPeers.add(peer);
                if (isNew) {
                    // Match Python's "Discovered peer: {...}" format
                    System.out.println("Discovered peer: {'name': '" + name
                            + "._cisc468share._tcp.local.', 'address': '" + address
                            + "', 'port': " + port + "}");
                }
            }
        });
    }
    public List<PeerInfo> getDiscoveredPeers() {
        synchronized (discoveredPeers) {
            return new ArrayList<>(discoveredPeers);
        }
    }

}
