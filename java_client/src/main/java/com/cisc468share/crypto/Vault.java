package com.cisc468share.crypto;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class Vault {

    public static byte[] deriveKey(String password, byte[] salt) throws Exception {

        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 200000, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

        return factory.generateSecret(spec).getEncoded();
    }

    public static String encrypt(byte[] data, String password) throws Exception {

        SecureRandom random = new SecureRandom();

        byte[] salt = new byte[16];
        byte[] nonce = new byte[12];

        random.nextBytes(salt);
        random.nextBytes(nonce);

        byte[] key = deriveKey(password, salt);

        byte[] ct = AesGcmUtil.encrypt(key, nonce, data, null);

        return Base64.getEncoder().encodeToString(ct);
    }
}
