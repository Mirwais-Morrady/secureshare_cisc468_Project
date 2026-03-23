package com.cisc468share.net;

import com.cisc468share.crypto.DhParams;
import com.cisc468share.crypto.HashUtil;
import com.cisc468share.crypto.HkdfUtil;
import com.cisc468share.crypto.SecureSession;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Map;

public class SessionManager {

    public static BigInteger generatePrivate() {
        BigInteger x;
        do {
            x = new BigInteger(256, new SecureRandom());
        } while (x.signum() <= 0);
        return x;
    }

    public static BigInteger computePublic(BigInteger privateKey) {
        return DhParams.GROUP14_G.modPow(privateKey, DhParams.GROUP14_P);
    }

    public static byte[] computeShared(BigInteger privateKey, BigInteger peerPublic) {
        BigInteger shared = peerPublic.modPow(privateKey, DhParams.GROUP14_P);
        return DhParams.intToFixedLengthBytes(shared);
    }

    public static SecureSession deriveSession(byte[] shared, byte[] transcript, boolean initiator) {
        Map<String, byte[]> keys = HkdfUtil.deriveSessionMaterial(shared, transcript);

        byte[] sendKey = initiator
                ? keys.get("client_to_server_key")
                : keys.get("server_to_client_key");

        byte[] recvKey = initiator
                ? keys.get("server_to_client_key")
                : keys.get("client_to_server_key");

        return new SecureSession(
                HashUtil.toHex(keys.get("session_id_material")),
                sendKey,
                recvKey
        );
    }
}
