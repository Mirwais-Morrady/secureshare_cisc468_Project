package com.cisc468share.crypto;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

public class Vault {

    public static byte[] deriveKey(String password, byte[] salt) throws Exception {

        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 200000, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

        return factory.generateSecret(spec).getEncoded();
    }

    public static String encrypt(byte[] data, String password) throws Exception {
        return Base64.getEncoder().encodeToString(encryptVault(password, data));
    }

    public static byte[] encryptVault(String password, byte[] plaintext) throws Exception {
        SecureRandom random = new SecureRandom();

        byte[] salt = new byte[16];
        byte[] nonce = new byte[12];
        random.nextBytes(salt);
        random.nextBytes(nonce);

        byte[] key = deriveKey(password, salt);
        byte[] ciphertext = AesGcmUtil.encrypt(key, nonce, plaintext, null);

        byte[] out = new byte[salt.length + nonce.length + ciphertext.length];
        System.arraycopy(salt, 0, out, 0, salt.length);
        System.arraycopy(nonce, 0, out, salt.length, nonce.length);
        System.arraycopy(ciphertext, 0, out, salt.length + nonce.length, ciphertext.length);
        return out;
    }

    public static byte[] decryptVault(String password, byte[] data) throws Exception {
        if (data.length < 29) {
            throw new IllegalArgumentException("vault payload too short");
        }

        byte[] salt = Arrays.copyOfRange(data, 0, 16);
        byte[] nonce = Arrays.copyOfRange(data, 16, 28);
        byte[] ciphertext = Arrays.copyOfRange(data, 28, data.length);
        byte[] key = deriveKey(password, salt);
        return AesGcmUtil.decrypt(key, nonce, ciphertext, null);
    }
}
