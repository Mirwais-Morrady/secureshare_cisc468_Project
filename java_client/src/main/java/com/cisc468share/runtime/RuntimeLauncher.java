package com.cisc468share.runtime;

import com.cisc468share.cli.CommandLine;
import com.cisc468share.discovery.MdnsService;
import com.cisc468share.crypto.IdentityManager;
import com.cisc468share.crypto.HashUtil;
import com.cisc468share.crypto.HandshakeManager;
import com.cisc468share.files.ShareManager;
import com.cisc468share.net.*;

import java.nio.file.Paths;
import java.security.KeyPair;

public class RuntimeLauncher {

    public void run() throws Exception {

        MdnsService mdns = new MdnsService();
        mdns.start("java-peer",40469);

        KeyPair keyPair = IdentityManager.generateRSA();
        byte[] publicKeyDer = keyPair.getPublic().getEncoded();
        String peerId = HashUtil.sha256Hex(publicKeyDer);
        String peerName = "java-peer";

        HandshakeManager handshakeManager = new HandshakeManager(peerName, peerId, publicKeyDer, keyPair.getPrivate());

        ShareManager shareManager = new ShareManager(Paths.get("data", "shared"));

        TcpServer server = new TcpServer(40469,new ConnectionHandler(handshakeManager, shareManager));

        new Thread(() -> {

            try {
                server.start();
            } catch(Exception e) {
                e.printStackTrace();
            }

        }).start();

        CommandLine cli = new CommandLine(shareManager, mdns);

        cli.start();

    }
}
