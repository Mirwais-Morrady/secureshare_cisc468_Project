package com.cisc468share.crypto;

import com.cisc468share.net.SessionManager;
import com.cisc468share.protocol.HandshakeUtil;
import com.cisc468share.protocol.Serializer;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class HandshakeManagerTest {

    @Test
    public void testBuildClientHelloContainsRequiredFields() throws Exception {
        KeyPair kp = IdentityManager.generateRSA();
        byte[] pubDer = kp.getPublic().getEncoded();
        String peerId = IdentityManager.fingerprint(pubDer);

        BigInteger dhPrivate = SessionManager.generatePrivate();
        BigInteger dhPublic = SessionManager.computePublic(dhPrivate);
        byte[] nonce = new byte[16];
        new SecureRandom().nextBytes(nonce);

        Map<String, Object> hello = HandshakeUtil.buildClientHello(
                "test-peer", peerId, pubDer, dhPublic, nonce, kp.getPrivate());

        assertEquals("CLIENT_HELLO", hello.get("type"));
        assertEquals("1.0", hello.get("proto_ver"));
        assertTrue(hello.containsKey("peer_name"));
        assertTrue(hello.containsKey("peer_id"));
        assertTrue(hello.containsKey("rsa_public_key_der_b64"));
        assertTrue(hello.containsKey("dh_public_b64"));
        assertTrue(hello.containsKey("nonce1_b64"));
        assertTrue(hello.containsKey("signature_b64"));
    }

    @Test
    public void testBuildServerHelloContainsRequiredFields() throws Exception {
        KeyPair kp = IdentityManager.generateRSA();
        byte[] pubDer = kp.getPublic().getEncoded();
        String peerId = IdentityManager.fingerprint(pubDer);

        BigInteger dhPrivate = SessionManager.generatePrivate();
        BigInteger dhPublic = SessionManager.computePublic(dhPrivate);
        byte[] nonce2 = new byte[16];
        byte[] clientNonce1 = new byte[16];
        new SecureRandom().nextBytes(nonce2);
        new SecureRandom().nextBytes(clientNonce1);

        Map<String, Object> hello = HandshakeUtil.buildServerHello(
                "test-peer", peerId, pubDer, dhPublic, nonce2, clientNonce1, kp.getPrivate());

        assertEquals("SERVER_HELLO", hello.get("type"));
        assertEquals("1.0", hello.get("proto_ver"));
        assertTrue(hello.containsKey("nonce2_b64"));
        assertTrue(hello.containsKey("client_nonce1_b64"));
        assertTrue(hello.containsKey("signature_b64"));
    }

    @Test
    public void testSignAndVerifyClientHello() throws Exception {
        KeyPair kp = IdentityManager.generateRSA();
        byte[] pubDer = kp.getPublic().getEncoded();
        String peerId = IdentityManager.fingerprint(pubDer);

        BigInteger dhPrivate = SessionManager.generatePrivate();
        BigInteger dhPublic = SessionManager.computePublic(dhPrivate);
        byte[] nonce = new byte[16];
        new SecureRandom().nextBytes(nonce);

        Map<String, Object> hello = HandshakeUtil.buildClientHello(
                "test-peer", peerId, pubDer, dhPublic, nonce, kp.getPrivate());

        // Verify the signature
        LinkedHashMap<String, Object> unsigned = new LinkedHashMap<>(hello);
        String sigB64 = (String) unsigned.remove("signature_b64");
        byte[] sig = Base64.getDecoder().decode(sigB64);
        byte[] signedData = Serializer.jsonDumpsBytes(unsigned);

        assertTrue(IdentityManager.verify(kp.getPublic(), signedData, sig));
    }

    @Test
    public void testTranscriptHashIsDeterministic() throws Exception {
        KeyPair kpC = IdentityManager.generateRSA();
        KeyPair kpS = IdentityManager.generateRSA();

        BigInteger cDhPriv = SessionManager.generatePrivate();
        BigInteger cDhPub = SessionManager.computePublic(cDhPriv);
        BigInteger sDhPriv = SessionManager.generatePrivate();
        BigInteger sDhPub = SessionManager.computePublic(sDhPriv);

        byte[] nonce1 = new byte[16];
        byte[] nonce2 = new byte[16];
        new SecureRandom().nextBytes(nonce1);
        new SecureRandom().nextBytes(nonce2);

        Map<String, Object> clientHello = HandshakeUtil.buildClientHello(
                "client", IdentityManager.fingerprint(kpC.getPublic().getEncoded()),
                kpC.getPublic().getEncoded(), cDhPub, nonce1, kpC.getPrivate());

        Map<String, Object> serverHello = HandshakeUtil.buildServerHello(
                "server", IdentityManager.fingerprint(kpS.getPublic().getEncoded()),
                kpS.getPublic().getEncoded(), sDhPub, nonce2, nonce1, kpS.getPrivate());

        byte[] hash1 = HandshakeUtil.transcriptHash(clientHello, serverHello);
        byte[] hash2 = HandshakeUtil.transcriptHash(clientHello, serverHello);
        assertArrayEquals(hash1, hash2);
    }

    @Test
    public void testFullSessionDerivation() throws Exception {
        KeyPair kpC = IdentityManager.generateRSA();
        KeyPair kpS = IdentityManager.generateRSA();
        byte[] cPubDer = kpC.getPublic().getEncoded();
        byte[] sPubDer = kpS.getPublic().getEncoded();

        BigInteger cDhPriv = SessionManager.generatePrivate();
        BigInteger cDhPub = SessionManager.computePublic(cDhPriv);
        BigInteger sDhPriv = SessionManager.generatePrivate();
        BigInteger sDhPub = SessionManager.computePublic(sDhPriv);

        byte[] nonce1 = new byte[16];
        byte[] nonce2 = new byte[16];
        new SecureRandom().nextBytes(nonce1);
        new SecureRandom().nextBytes(nonce2);

        Map<String, Object> clientHello = HandshakeUtil.buildClientHello(
                "client", IdentityManager.fingerprint(cPubDer), cPubDer, cDhPub, nonce1, kpC.getPrivate());

        Map<String, Object> serverHello = HandshakeUtil.buildServerHello(
                "server", IdentityManager.fingerprint(sPubDer), sPubDer, sDhPub, nonce2, nonce1, kpS.getPrivate());

        byte[] transcript = HandshakeUtil.transcriptHash(clientHello, serverHello);

        byte[] clientShared = SessionManager.computeShared(cDhPriv, sDhPub);
        byte[] serverShared = SessionManager.computeShared(sDhPriv, cDhPub);
        assertArrayEquals(clientShared, serverShared, "Shared secrets must match");

        SecureSession clientSession = SessionManager.deriveSession(clientShared, transcript, true);
        SecureSession serverSession = SessionManager.deriveSession(serverShared, transcript, false);

        assertEquals(clientSession.sessionId, serverSession.sessionId, "Session IDs must match");
        assertArrayEquals(clientSession.sendKey, serverSession.recvKey, "Client sendKey must match server recvKey");
        assertArrayEquals(clientSession.recvKey, serverSession.sendKey, "Client recvKey must match server sendKey");
    }
}
