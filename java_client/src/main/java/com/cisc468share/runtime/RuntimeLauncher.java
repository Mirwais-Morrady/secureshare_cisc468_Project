package com.cisc468share.runtime;

import com.cisc468share.cli.CommandLine;
import com.cisc468share.discovery.MdnsService;
import com.cisc468share.crypto.IdentityManager;
import com.cisc468share.crypto.HashUtil;
import com.cisc468share.crypto.HandshakeManager;
import com.cisc468share.files.ShareManager;
import com.cisc468share.net.*;

import com.cisc468share.net.ConsentManager;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.util.Scanner;

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

        // Shared consent manager — background threads queue requests,
        // the main CLI thread handles the prompt and reads the response.
        ConsentManager consentManager = new ConsentManager();
        Scanner sharedScanner = new Scanner(System.in);

        TcpServer server = new TcpServer(40469, new ConnectionHandler(handshakeManager, shareManager, consentManager));

        new Thread(() -> {
            try {
                server.start();
            } catch(Exception e) {
                e.printStackTrace();
            }
        }).start();

        CommandLine cli = new CommandLine(shareManager, mdns, sharedScanner, consentManager);

        cli.start();

    }
}
