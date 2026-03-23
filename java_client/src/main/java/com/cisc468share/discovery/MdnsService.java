package com.cisc468share.discovery;

import javax.jmdns.JmDNS;
import javax.jmdns.ServiceInfo;
import java.io.IOException;
import java.net.InetAddress;

public class MdnsService {

    private JmDNS jmdns;

    public void start(String name, int port) throws IOException {

        jmdns = JmDNS.create(InetAddress.getLocalHost());

        ServiceInfo serviceInfo = ServiceInfo.create(
                "_cisc468share._tcp.local.",
                name,
                port,
                "Secure Share peer"
        );

        jmdns.registerService(serviceInfo);

        System.out.println("mDNS service registered: " + name);
    }
}
