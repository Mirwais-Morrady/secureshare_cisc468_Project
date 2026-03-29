package com.cisc468share.crypto;

import com.cisc468share.net.SessionManager;
import com.cisc468share.protocol.HandshakeUtil;
import com.cisc468share.protocol.Serializer;
import com.cisc468share.net.Framing;

import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Executes the full cryptographic handshake protocol.
 * The initiator sends CLIENT_HELLO, the responder sends SERVER_HELLO.
 */
public class HandshakeManager {

    /** Result of a completed handshake — session plus the remote peer's identity. */
    public static class HandshakeResult {
        public final SecureSession session;
        public final String remotePeerId;
        public final String remotePeerName;
        public final byte[] remotePublicKeyDer;

        public HandshakeResult(SecureSession session, String remotePeerId,
                               String remotePeerName, byte[] remotePublicKeyDer) {
            this.session = session;
            this.remotePeerId = remotePeerId;
            this.remotePeerName = remotePeerName;
            this.remotePublicKeyDer = remotePublicKeyDer;
        }
    }

    private final String peerName;
    private final String peerId;
    private final byte[] publicKeyDer;
    private final PrivateKey privateKey;

    public HandshakeManager(String peerName, String peerId, byte[] publicKeyDer, PrivateKey privateKey) {
        this.peerName = peerName;
        this.peerId = peerId;
        this.publicKeyDer = publicKeyDer;
        this.privateKey = privateKey;
    }

    /**
     * Execute the handshake as the CLIENT (initiator).
     * Sends CLIENT_HELLO, receives SERVER_HELLO, derives session.
     */
    public SecureSession executeClientHandshake(Socket socket) throws Exception {
        InputStream in = socket.getInputStream();
        OutputStream out = socket.getOutputStream();

        // Generate DH key pair
        BigInteger dhPrivate = SessionManager.generatePrivate();
        BigInteger dhPublic = SessionManager.computePublic(dhPrivate);
        byte[] nonce1 = new byte[16];
        new SecureRandom().nextBytes(nonce1);

        // Build CLIENT_HELLO
        Map<String, Object> clientHello = HandshakeUtil.buildClientHello(
                peerName, peerId, publicKeyDer, dhPublic, nonce1, privateKey);

        // Send CLIENT_HELLO
        byte[] payload = Serializer.jsonDumpsBytes(clientHello);
        out.write(Framing.encodeFrame(payload));
        out.flush();

        // Receive SERVER_HELLO
        byte[] rawServerHello = Framing.decodeFrame(in);
        Map<String, Object> serverHello = Serializer.jsonLoadsBytes(rawServerHello);

        if (!"SERVER_HELLO".equals(serverHello.get("type"))) {
            throw new IllegalStateException("Expected SERVER_HELLO, got: " + serverHello.get("type"));
        }
        if (!"1.0".equals(serverHello.get("proto_ver"))) {
            throw new IllegalStateException("Unsupported protocol version: " + serverHello.get("proto_ver"));
        }

        // Verify SERVER_HELLO signature
        byte[] serverPubDer = Base64.getDecoder().decode((String) serverHello.get("rsa_public_key_der_b64"));
        PublicKey serverPublicKey = KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(serverPubDer));

        Map<String, Object> unsigned = new LinkedHashMap<>(serverHello);
        unsigned.remove("signature_b64");
        byte[] signedData = Serializer.jsonDumpsBytes(unsigned);
        byte[] sig = Base64.getDecoder().decode((String) serverHello.get("signature_b64"));
        if (!IdentityManager.verify(serverPublicKey, signedData, sig)) {
            throw new SecurityException("SERVER_HELLO signature verification failed");
        }

        // Compute shared secret
        byte[] serverDhPubBytes = Base64.getDecoder().decode((String) serverHello.get("dh_public_b64"));
        BigInteger serverDhPublic = new BigInteger(1, serverDhPubBytes);
        byte[] sharedSecret = SessionManager.computeShared(dhPrivate, serverDhPublic);

        // Compute transcript hash and derive session
        byte[] transcript = HandshakeUtil.transcriptHash(clientHello, serverHello);
        SecureSession session = SessionManager.deriveSession(sharedSecret, transcript, true);
        return session;
    }

    /**
     * Execute the handshake as the CLIENT and return full HandshakeResult including
     * the remote peer's identity information.
     */
    public HandshakeResult executeClientHandshakeEx(Socket socket) throws Exception {
        InputStream in = socket.getInputStream();
        OutputStream out = socket.getOutputStream();

        BigInteger dhPrivate = SessionManager.generatePrivate();
        BigInteger dhPublic = SessionManager.computePublic(dhPrivate);
        byte[] nonce1 = new byte[16];
        new SecureRandom().nextBytes(nonce1);

        Map<String, Object> clientHello = HandshakeUtil.buildClientHello(
                peerName, peerId, publicKeyDer, dhPublic, nonce1, privateKey);

        byte[] payload = Serializer.jsonDumpsBytes(clientHello);
        out.write(Framing.encodeFrame(payload));
        out.flush();

        byte[] rawServerHello = Framing.decodeFrame(in);
        Map<String, Object> serverHello = Serializer.jsonLoadsBytes(rawServerHello);

        if (!"SERVER_HELLO".equals(serverHello.get("type")))
            throw new IllegalStateException("Expected SERVER_HELLO, got: " + serverHello.get("type"));
        if (!"1.0".equals(serverHello.get("proto_ver")))
            throw new IllegalStateException("Unsupported protocol version: " + serverHello.get("proto_ver"));

        byte[] serverPubDer = Base64.getDecoder().decode((String) serverHello.get("rsa_public_key_der_b64"));
        PublicKey serverPublicKey = KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(serverPubDer));

        Map<String, Object> unsigned = new LinkedHashMap<>(serverHello);
        unsigned.remove("signature_b64");
        byte[] signedData = Serializer.jsonDumpsBytes(unsigned);
        byte[] sig = Base64.getDecoder().decode((String) serverHello.get("signature_b64"));
        if (!IdentityManager.verify(serverPublicKey, signedData, sig))
            throw new SecurityException("SERVER_HELLO signature verification failed");

        byte[] serverDhPubBytes = Base64.getDecoder().decode((String) serverHello.get("dh_public_b64"));
        BigInteger serverDhPublic = new BigInteger(1, serverDhPubBytes);
        byte[] sharedSecret = SessionManager.computeShared(dhPrivate, serverDhPublic);

        byte[] transcript = HandshakeUtil.transcriptHash(clientHello, serverHello);
        SecureSession session = SessionManager.deriveSession(sharedSecret, transcript, true);

        String remotePeerId   = (String) serverHello.getOrDefault("peer_id", "unknown");
        String remotePeerName = (String) serverHello.getOrDefault("peer_name", "unknown");

        return new HandshakeResult(session, remotePeerId, remotePeerName, serverPubDer);
    }

    /**
     * Execute the handshake as the SERVER (responder).
     * Receives CLIENT_HELLO, sends SERVER_HELLO, derives session.
     */
    public SecureSession executeServerHandshake(Socket socket) throws Exception {
        InputStream in = socket.getInputStream();
        OutputStream out = socket.getOutputStream();

        // Receive CLIENT_HELLO
        byte[] rawClientHello = Framing.decodeFrame(in);
        Map<String, Object> clientHello = Serializer.jsonLoadsBytes(rawClientHello);

        if (!"CLIENT_HELLO".equals(clientHello.get("type"))) {
            throw new IllegalStateException("Expected CLIENT_HELLO, got: " + clientHello.get("type"));
        }
        if (!"1.0".equals(clientHello.get("proto_ver"))) {
            throw new IllegalStateException("Unsupported protocol version: " + clientHello.get("proto_ver"));
        }

        // Verify CLIENT_HELLO signature
        byte[] clientPubDer = Base64.getDecoder().decode((String) clientHello.get("rsa_public_key_der_b64"));
        PublicKey clientPublicKey = KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(clientPubDer));

        Map<String, Object> unsigned = new LinkedHashMap<>(clientHello);
        unsigned.remove("signature_b64");
        byte[] signedData = Serializer.jsonDumpsBytes(unsigned);
        byte[] sig = Base64.getDecoder().decode((String) clientHello.get("signature_b64"));
        if (!IdentityManager.verify(clientPublicKey, signedData, sig)) {
            throw new SecurityException("CLIENT_HELLO signature verification failed");
        }

        // Generate DH key pair for server
        BigInteger dhPrivate = SessionManager.generatePrivate();
        BigInteger dhPublic = SessionManager.computePublic(dhPrivate);
        byte[] nonce2 = new byte[16];
        new SecureRandom().nextBytes(nonce2);
        byte[] clientNonce1 = Base64.getDecoder().decode((String) clientHello.get("nonce1_b64"));

        // Build and send SERVER_HELLO
        Map<String, Object> serverHello = HandshakeUtil.buildServerHello(
                peerName, peerId, publicKeyDer, dhPublic, nonce2, clientNonce1, privateKey);

        byte[] payload = Serializer.jsonDumpsBytes(serverHello);
        out.write(Framing.encodeFrame(payload));
        out.flush();

        // Compute shared secret
        byte[] clientDhPubBytes = Base64.getDecoder().decode((String) clientHello.get("dh_public_b64"));
        BigInteger clientDhPublic = new BigInteger(1, clientDhPubBytes);
        byte[] sharedSecret = SessionManager.computeShared(dhPrivate, clientDhPublic);

        // Compute transcript hash and derive session
        byte[] transcript = HandshakeUtil.transcriptHash(clientHello, serverHello);
        return SessionManager.deriveSession(sharedSecret, transcript, false); // false = responder
    }

    /**
     * Execute the handshake as the SERVER and return full HandshakeResult including
     * the remote client's identity information.
     */
    public HandshakeResult executeServerHandshakeEx(Socket socket) throws Exception {
        InputStream in = socket.getInputStream();
        OutputStream out = socket.getOutputStream();

        byte[] rawClientHello = Framing.decodeFrame(in);
        Map<String, Object> clientHello = Serializer.jsonLoadsBytes(rawClientHello);

        if (!"CLIENT_HELLO".equals(clientHello.get("type")))
            throw new IllegalStateException("Expected CLIENT_HELLO, got: " + clientHello.get("type"));
        if (!"1.0".equals(clientHello.get("proto_ver")))
            throw new IllegalStateException("Unsupported protocol version: " + clientHello.get("proto_ver"));

        byte[] clientPubDer = Base64.getDecoder().decode((String) clientHello.get("rsa_public_key_der_b64"));
        PublicKey clientPublicKey = KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(clientPubDer));

        Map<String, Object> unsigned = new LinkedHashMap<>(clientHello);
        unsigned.remove("signature_b64");
        byte[] signedData = Serializer.jsonDumpsBytes(unsigned);
        byte[] sig = Base64.getDecoder().decode((String) clientHello.get("signature_b64"));
        if (!IdentityManager.verify(clientPublicKey, signedData, sig))
            throw new SecurityException("CLIENT_HELLO signature verification failed");

        BigInteger dhPrivate = SessionManager.generatePrivate();
        BigInteger dhPublic = SessionManager.computePublic(dhPrivate);
        byte[] nonce2 = new byte[16];
        new SecureRandom().nextBytes(nonce2);
        byte[] clientNonce1 = Base64.getDecoder().decode((String) clientHello.get("nonce1_b64"));

        Map<String, Object> serverHello = HandshakeUtil.buildServerHello(
                peerName, peerId, publicKeyDer, dhPublic, nonce2, clientNonce1, privateKey);

        byte[] payload = Serializer.jsonDumpsBytes(serverHello);
        out.write(Framing.encodeFrame(payload));
        out.flush();

        byte[] clientDhPubBytes = Base64.getDecoder().decode((String) clientHello.get("dh_public_b64"));
        BigInteger clientDhPublic = new BigInteger(1, clientDhPubBytes);
        byte[] sharedSecret = SessionManager.computeShared(dhPrivate, clientDhPublic);

        byte[] transcript = HandshakeUtil.transcriptHash(clientHello, serverHello);
        SecureSession session = SessionManager.deriveSession(sharedSecret, transcript, false);

        String remotePeerId   = (String) clientHello.getOrDefault("peer_id", "unknown");
        String remotePeerName = (String) clientHello.getOrDefault("peer_name", "unknown");

        return new HandshakeResult(session, remotePeerId, remotePeerName, clientPubDer);
    }
}
