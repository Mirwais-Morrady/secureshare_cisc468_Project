package com.cisc468share.crypto;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.cisc468share.storage.VaultStore;

import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * REQUIREMENT 9 — Secure Local Storage (Java VaultStore)
 *
 * Verifies that:
 * - PBKDF2-HMAC-SHA256 + AES-256-GCM encryption is used for vault files
 * - Correct password decrypts successfully
 * - Wrong password causes an exception
 * - Tampered vault data is detected
 * - Each encryption produces a unique ciphertext (random salt + nonce)
 * - VaultStore persists, lists, retrieves, and deletes files correctly
 */
public class VaultTest {

    // ── Low-level Vault crypto ────────────────────────────────────────────────

    @Test
    public void testEncryptDecryptRoundtrip() throws Exception {
        byte[] plaintext = "Confidential file contents".getBytes();
        byte[] blob = Vault.encryptVault("correct-password", plaintext);
        byte[] recovered = Vault.decryptVault("correct-password", blob);
        assertArrayEquals(plaintext, recovered, "Encrypt→decrypt must recover original data");
    }

    @Test
    public void testEncryptedBlobDoesNotContainPlaintext() throws Exception {
        byte[] plaintext = "supersecret document".getBytes();
        byte[] blob = Vault.encryptVault("password", plaintext);
        // The blob must not contain the plaintext as a contiguous subsequence
        String blobStr = new String(blob);
        assertFalse(blobStr.contains("supersecret"), "Plaintext must not appear in encrypted blob");
    }

    @Test
    public void testWrongPasswordRejected() throws Exception {
        byte[] blob = Vault.encryptVault("correct", "secret data".getBytes());
        assertThrows(Exception.class, () -> Vault.decryptVault("wrong", blob),
                "Wrong password must cause decryption failure");
    }

    @Test
    public void testTamperedBlobDetected() throws Exception {
        byte[] blob = Vault.encryptVault("password", "data".getBytes());
        blob[30] ^= (byte) 0xFF;   // flip a byte in the ciphertext region
        assertThrows(Exception.class, () -> Vault.decryptVault("password", blob),
                "Tampered ciphertext must be detected by AEAD tag");
    }

    @Test
    public void testDifferentEncryptionsProduceDifferentBlobs() throws Exception {
        byte[] p = "identical content".getBytes();
        byte[] blob1 = Vault.encryptVault("password", p);
        byte[] blob2 = Vault.encryptVault("password", p);
        assertFalse(Arrays.equals(blob1, blob2),
                "Each encryption must be unique (random salt + nonce)");
    }

    @Test
    public void testBlobMinimumLength() throws Exception {
        // 16 bytes salt + 12 bytes nonce + 16 bytes GCM tag = 44 minimum
        byte[] blob = Vault.encryptVault("password", new byte[0]);
        assertTrue(blob.length >= 44,
                "Blob must be at least 44 bytes (salt + nonce + GCM tag)");
    }

    @Test
    public void testLargeFileRoundtrip() throws Exception {
        byte[] large = new byte[1024 * 1024];
        Arrays.fill(large, (byte) 0xAB);
        byte[] blob = Vault.encryptVault("strongpass", large);
        byte[] recovered = Vault.decryptVault("strongpass", blob);
        assertArrayEquals(large, recovered, "1 MB file must survive vault round-trip");
    }

    // ── VaultStore (file-system level) ───────────────────────────────────────

    @Test
    public void testVaultStoreStoreAndRetrieve(@TempDir Path tmp) {
        VaultStore vault = new VaultStore(tmp, "testpassword123");
        byte[] original = "Sensitive document".getBytes();
        vault.storeFile("doc.txt", original);
        byte[] retrieved = vault.getFile("doc.txt");
        assertArrayEquals(original, retrieved, "VaultStore must return original bytes");
    }

    @Test
    public void testVaultStoreFileOnDiskIsEncrypted(@TempDir Path tmp) throws Exception {
        VaultStore vault = new VaultStore(tmp, "password");
        byte[] plaintext = "Do not read without decryption".getBytes();
        vault.storeFile("secret.txt", plaintext);
        byte[] raw = java.nio.file.Files.readAllBytes(tmp.resolve("secret.txt.enc"));
        // Raw bytes must not contain the plaintext
        String rawStr = new String(raw);
        assertFalse(rawStr.contains("Do not read"), "Plaintext must not appear in .enc file");
    }

    @Test
    public void testVaultStoreListFiles(@TempDir Path tmp) {
        VaultStore vault = new VaultStore(tmp, "pw");
        vault.storeFile("a.txt", "aaa".getBytes());
        vault.storeFile("b.txt", "bbb".getBytes());
        var files = vault.listFiles();
        assertTrue(files.contains("a.txt"), "list must include a.txt");
        assertTrue(files.contains("b.txt"), "list must include b.txt");
    }

    @Test
    public void testVaultStoreDeleteFile(@TempDir Path tmp) {
        VaultStore vault = new VaultStore(tmp, "pw");
        vault.storeFile("temp.txt", "temporary".getBytes());
        vault.deleteFile("temp.txt");
        assertFalse(vault.listFiles().contains("temp.txt"), "Deleted file must not appear in list");
        assertFalse(tmp.resolve("temp.txt.enc").toFile().exists(), ".enc file must be removed");
    }

    @Test
    public void testVaultStoreWrongPasswordFails(@TempDir Path tmp) {
        VaultStore correct = new VaultStore(tmp, "correct");
        correct.storeFile("locked.txt", "contents".getBytes());
        VaultStore wrong = new VaultStore(tmp, "wrong");
        assertThrows(Exception.class, () -> wrong.getFile("locked.txt"),
                "Wrong password vault must fail on get");
    }

    @Test
    public void testEmptyVaultListIsEmpty(@TempDir Path tmp) {
        VaultStore vault = new VaultStore(tmp, "pw");
        assertTrue(vault.listFiles().isEmpty(), "New vault must have no files");
    }
}
