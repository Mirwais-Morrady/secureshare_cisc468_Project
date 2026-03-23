package com.cisc468share.crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Base64;

public class IdentityManager {

    private static final PSSParameterSpec PSS_SHA256 = new PSSParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA256,
            32,
            1
    );

    public static KeyPair generateRSA() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    public static byte[] sign(PrivateKey key, byte[] data) throws Exception {
        Signature sig = Signature.getInstance("RSASSA-PSS");
        sig.setParameter(PSS_SHA256);
        sig.initSign(key);
        sig.update(data);
        return sig.sign();
    }

    public static boolean verify(PublicKey key, byte[] data, byte[] signature) throws Exception {
        Signature sig = Signature.getInstance("RSASSA-PSS");
        sig.setParameter(PSS_SHA256);
        sig.initVerify(key);
        sig.update(data);
        return sig.verify(signature);
    }

    public static String fingerprint(byte[] publicKeyDer) {
        return HashUtil.sha256Hex(publicKeyDer);
    }

    public static String toBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }
}
