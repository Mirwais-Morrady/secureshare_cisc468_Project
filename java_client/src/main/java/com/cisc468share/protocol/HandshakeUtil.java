package com.cisc468share.protocol;

import com.cisc468share.crypto.DhParams;
import com.cisc468share.crypto.HashUtil;
import com.cisc468share.crypto.IdentityManager;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

public class HandshakeUtil {

    public static Map<String, Object> buildClientHello(
            String peerName,
            String peerId,
            byte[] publicKeyDer,
            BigInteger dhPublic,
            byte[] nonce1,
            PrivateKey privateKey
    ) throws Exception {

        Map<String, Object> msg = new LinkedHashMap<>();
        msg.put("type", "CLIENT_HELLO");
        msg.put("proto_ver", "1.0");
        msg.put("peer_name", peerName);
        msg.put("peer_id", peerId);
        msg.put("rsa_public_key_der_b64", Base64.getEncoder().encodeToString(publicKeyDer));
        msg.put("dh_public_b64", Base64.getEncoder().encodeToString(DhParams.intToFixedLengthBytes(dhPublic)));
        msg.put("nonce1_b64", Base64.getEncoder().encodeToString(nonce1));

        byte[] signature = IdentityManager.sign(privateKey, Serializer.jsonDumpsBytes(msg));
        msg.put("signature_b64", Base64.getEncoder().encodeToString(signature));
        return msg;
    }

    public static Map<String, Object> buildServerHello(
            String peerName,
            String peerId,
            byte[] publicKeyDer,
            BigInteger dhPublic,
            byte[] nonce2,
            byte[] clientNonce1,
            PrivateKey privateKey
    ) throws Exception {

        Map<String, Object> msg = new LinkedHashMap<>();
        msg.put("type", "SERVER_HELLO");
        msg.put("proto_ver", "1.0");
        msg.put("peer_name", peerName);
        msg.put("peer_id", peerId);
        msg.put("rsa_public_key_der_b64", Base64.getEncoder().encodeToString(publicKeyDer));
        msg.put("dh_public_b64", Base64.getEncoder().encodeToString(DhParams.intToFixedLengthBytes(dhPublic)));
        msg.put("nonce2_b64", Base64.getEncoder().encodeToString(nonce2));
        msg.put("client_nonce1_b64", Base64.getEncoder().encodeToString(clientNonce1));

        byte[] signature = IdentityManager.sign(privateKey, Serializer.jsonDumpsBytes(msg));
        msg.put("signature_b64", Base64.getEncoder().encodeToString(signature));
        return msg;
    }

    public static byte[] transcriptHash(Map<String, Object> clientHello, Map<String, Object> serverHello) {
        byte[] combined = new byte[CanonicalJson.toBytes(clientHello).length + CanonicalJson.toBytes(serverHello).length];
        byte[] clientBytes = CanonicalJson.toBytes(clientHello);
        byte[] serverBytes = CanonicalJson.toBytes(serverHello);

        System.arraycopy(clientBytes, 0, combined, 0, clientBytes.length);
        System.arraycopy(serverBytes, 0, combined, clientBytes.length, serverBytes.length);

        return HashUtil.sha256Bytes(combined);
    }
}
