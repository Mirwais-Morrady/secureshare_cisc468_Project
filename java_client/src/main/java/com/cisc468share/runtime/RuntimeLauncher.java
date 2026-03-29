package com.cisc468share.runtime;

import com.cisc468share.cli.CommandLine;
import com.cisc468share.discovery.MdnsService;
import com.cisc468share.crypto.HashUtil;
import com.cisc468share.crypto.HandshakeManager;
import com.cisc468share.crypto.IdentityManager;
import com.cisc468share.files.ShareManager;
import com.cisc468share.net.*;
import com.cisc468share.net.ConsentManager;
import com.cisc468share.storage.ContactsStore;
import com.cisc468share.storage.ManifestStore;

import java.net.ServerSocket;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class RuntimeLauncher {

    public void run() throws Exception {

        // ------------------------------------------------------------------ //
        // Load or generate persistent RSA identity                           //
        // ------------------------------------------------------------------ //
        Path identityDir = Paths.get("data", "identity");
        Files.createDirectories(identityDir);
        Path privKeyPath = identityDir.resolve("private_key.pem");
        Path pubKeyPath  = identityDir.resolve("public_key.pem");

        PrivateKey privateKey;
        PublicKey  publicKey;

        if (Files.exists(privKeyPath) && Files.exists(pubKeyPath)) {
            privateKey = loadPrivateKeyPem(privKeyPath);
            publicKey  = loadPublicKeyPem(pubKeyPath);
        } else {
            KeyPair kp = IdentityManager.generateRSA();
            privateKey = kp.getPrivate();
            publicKey  = kp.getPublic();
            savePrivateKeyPem(privateKey, privKeyPath);
            savePublicKeyPem(publicKey,  pubKeyPath);
        }

        byte[] publicKeyDer = publicKey.getEncoded();
        String peerId   = HashUtil.sha256Hex(publicKeyDer);
        String peerName = "java-peer";

        // Bind to any available port now — pass socket directly to TcpServer
        // so there is no race between port selection and binding.
        ServerSocket serverSocket = new ServerSocket(0);
        serverSocket.setReuseAddress(true);
        int port = serverSocket.getLocalPort();

        // Start mDNS advertisement + discovery using the already-bound port
        MdnsService mdns = new MdnsService();
        mdns.start(peerName, port);

        // Startup messages — match Python's format
        System.out.println("[INFO] Identity: " + peerName);
        System.out.println("[INFO] Peer ID:  " + peerId);

        HandshakeManager handshakeManager = new HandshakeManager(
                peerName, peerId, publicKeyDer, privateKey);

        ShareManager   shareManager   = new ShareManager(Paths.get("data", "shared"));
        ManifestStore  manifestStore  = new ManifestStore(Paths.get("data", "manifests.json"));
        ContactsStore  contactsStore  = new ContactsStore(Paths.get("data", "contacts.json"));
        ConsentManager consentManager = new ConsentManager();
        Scanner        sharedScanner  = new Scanner(System.in);

        // TcpServer prints "TCP server listening on 0.0.0.0:<port>"
        TcpServer server = new TcpServer(serverSocket,
                new ConnectionHandler(handshakeManager, shareManager, consentManager, contactsStore));

        new Thread(() -> {
            try { server.start(); } catch (Exception e) { e.printStackTrace(); }
        }).start();

        // Give the server thread a moment to print its startup line before CLI starts
        Thread.sleep(50);
        System.out.println("[INFO] Listening on port " + port);

        CommandLine cli = new CommandLine(
                shareManager, mdns, sharedScanner, consentManager,
                peerName, peerId, publicKeyDer, privateKey, identityDir,
                manifestStore, contactsStore);

        cli.start();
    }

    // ------------------------------------------------------------------ //
    // PEM helpers                                                          //
    // ------------------------------------------------------------------ //

    public static void savePrivateKeyPem(PrivateKey key, Path path) throws Exception {
        byte[] der = key.getEncoded();
        String b64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(der);
        Files.writeString(path,
                "-----BEGIN PRIVATE KEY-----\n" + b64 + "\n-----END PRIVATE KEY-----\n");
    }

    public static void savePublicKeyPem(PublicKey key, Path path) throws Exception {
        byte[] der = key.getEncoded();
        String b64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(der);
        Files.writeString(path,
                "-----BEGIN PUBLIC KEY-----\n" + b64 + "\n-----END PUBLIC KEY-----\n");
    }

    static PrivateKey loadPrivateKeyPem(Path path) throws Exception {
        String pem = Files.readString(path);
        byte[] der = Base64.getDecoder().decode(
                pem.replace("-----BEGIN PRIVATE KEY-----", "")
                   .replace("-----END PRIVATE KEY-----", "")
                   .replaceAll("\\s", ""));
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    static PublicKey loadPublicKeyPem(Path path) throws Exception {
        String pem = Files.readString(path);
        byte[] der = Base64.getDecoder().decode(
                pem.replace("-----BEGIN PUBLIC KEY-----", "")
                   .replace("-----END PUBLIC KEY-----", "")
                   .replaceAll("\\s", ""));
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
    }
}
