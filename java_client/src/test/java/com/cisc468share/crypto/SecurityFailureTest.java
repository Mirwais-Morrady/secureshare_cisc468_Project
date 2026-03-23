package com.cisc468share.crypto;

import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for security failure scenarios (Requirement 10).
 *
 * Verifies that security checks fail loudly and correctly:
 * - Wrong key for signature verification
 * - Tampered ciphertext detected by AES-GCM
 * - Modified AAD detected by AES-GCM
 */
public class SecurityFailureTest {

    @Test
    public void testWrongKeySignatureVerificationFails() throws Exception {
        KeyPair kp1 = IdentityManager.generateRSA();
        KeyPair kp2 = IdentityManager.generateRSA();

        byte[] data = "test message".getBytes();
        byte[] sig = IdentityManager.sign(kp1.getPrivate(), data);

        // Verifying kp1's signature with kp2's public key must fail
        assertFalse(IdentityManager.verify(kp2.getPublic(), data, sig),
                "Cross-key signature verification must return false");
    }

    @Test
    public void testTamperedSignatureRejected() throws Exception {
        KeyPair kp = IdentityManager.generateRSA();
        byte[] data = "authentic message".getBytes();
        byte[] sig = IdentityManager.sign(kp.getPrivate(), data);

        // Flip a byte in the signature
        byte[] tampered = Arrays.copyOf(sig, sig.length);
        tampered[0] ^= (byte) 0xFF;

        assertFalse(IdentityManager.verify(kp.getPublic(), data, tampered),
                "Tampered signature must be rejected");
    }

    @Test
    public void testTamperedDataSignatureRejected() throws Exception {
        KeyPair kp = IdentityManager.generateRSA();
        byte[] data = "original data".getBytes();
        byte[] sig = IdentityManager.sign(kp.getPrivate(), data);

        byte[] tampered = "tampered data".getBytes();
        assertFalse(IdentityManager.verify(kp.getPublic(), tampered, sig),
                "Signature over tampered data must fail");
    }

    @Test
    public void testAesGcmTamperedCiphertextDetected() throws Exception {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] aad = "header".getBytes();
        byte[] plaintext = "secret".getBytes();

        byte[] ciphertext = AesGcmUtil.encrypt(key, nonce, plaintext, aad);

        // Flip a byte in the ciphertext
        byte[] tampered = Arrays.copyOf(ciphertext, ciphertext.length);
        tampered[0] ^= (byte) 0xFF;

        assertThrows(Exception.class,
                () -> AesGcmUtil.decrypt(key, nonce, tampered, aad),
                "Tampered ciphertext must be detected by AES-GCM");
    }

    @Test
    public void testAesGcmWrongAadDetected() throws Exception {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] aad = "correct-header".getBytes();
        byte[] plaintext = "message".getBytes();

        byte[] ciphertext = AesGcmUtil.encrypt(key, nonce, plaintext, aad);

        byte[] wrongAad = "wrong-header".getBytes();
        assertThrows(Exception.class,
                () -> AesGcmUtil.decrypt(key, nonce, ciphertext, wrongAad),
                "Wrong AAD must be detected by AES-GCM");
    }

    @Test
    public void testAesGcmWrongKeyDetected() throws Exception {
        byte[] key = new byte[32];
        byte[] wrongKey = new byte[32];
        wrongKey[0] = 1;
        byte[] nonce = new byte[12];
        byte[] aad = "header".getBytes();
        byte[] plaintext = "secret".getBytes();

        byte[] ciphertext = AesGcmUtil.encrypt(key, nonce, plaintext, aad);

        assertThrows(Exception.class,
                () -> AesGcmUtil.decrypt(wrongKey, nonce, ciphertext, aad),
                "Wrong decryption key must be detected");
    }
}
