package com.cisc468share.runtime;

import com.cisc468share.cli.CommandLine;
import com.cisc468share.discovery.MdnsService;
import com.cisc468share.net.*;

public class RuntimeLauncher {

    public void run() throws Exception {

        MdnsService mdns = new MdnsService();
        mdns.start("java-peer",40469);

        TcpServer server = new TcpServer(40469,new ConnectionHandler());

        new Thread(() -> {

            try {
                server.start();
            } catch(Exception e) {
                e.printStackTrace();
            }

        }).start();

        CommandLine cli = new CommandLine();

        cli.start();

    }
}
