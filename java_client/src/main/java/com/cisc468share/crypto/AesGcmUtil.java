package com.cisc468share.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AesGcmUtil {

    public static byte[] encrypt(byte[] key, byte[] nonce, byte[] plaintext, byte[] aad) throws Exception {

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, nonce);

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, spec);
        if (aad != null && aad.length > 0) {
            cipher.updateAAD(aad);
        }

        return cipher.doFinal(plaintext);
    }

    public static byte[] decrypt(byte[] key, byte[] nonce, byte[] ciphertext, byte[] aad) throws Exception {

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, nonce);

        cipher.init(Cipher.DECRYPT_MODE, keySpec, spec);
        if (aad != null && aad.length > 0) {
            cipher.updateAAD(aad);
        }

        return cipher.doFinal(ciphertext);
    }
}
