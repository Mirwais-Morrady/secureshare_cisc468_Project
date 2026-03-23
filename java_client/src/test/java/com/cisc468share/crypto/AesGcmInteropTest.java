package com.cisc468share.crypto;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class AesGcmInteropTest {

    private static final Path VECTORS = Paths.get(
            System.getProperty("project.root", "../../.."),
            "shared_test_vectors"
    );

    @SuppressWarnings("unchecked")
    private Map<String, Object> loadJson(Path path) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(Files.readString(path), Map.class);
    }

    @Test
    public void testAesGcmEncryptDecryptRoundtrip() throws Exception {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] aad = "header-data".getBytes(StandardCharsets.UTF_8);
        byte[] plaintext = "secret message".getBytes(StandardCharsets.UTF_8);

        byte[] ciphertext = AesGcmUtil.encrypt(key, nonce, plaintext, aad);
        byte[] decrypted = AesGcmUtil.decrypt(key, nonce, ciphertext, aad);

        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    public void testAesGcmVectorFile() throws Exception {
        Path vectorPath = VECTORS.resolve("aes_gcm/aes_gcm_vector.json");
        if (!vectorPath.toFile().exists()) return;

        Map<String, Object> data = loadJson(vectorPath);
        if (!data.containsKey("ciphertext_b64")) return;

        byte[] key = Base64.getDecoder().decode((String) data.get("key_b64"));
        byte[] nonce = Base64.getDecoder().decode((String) data.get("nonce_b64"));
        byte[] aad = Base64.getDecoder().decode((String) data.get("aad_b64"));
        byte[] plaintext = Base64.getDecoder().decode((String) data.get("plaintext_b64"));
        byte[] expectedCt = Base64.getDecoder().decode((String) data.get("ciphertext_b64"));

        byte[] actualCt = AesGcmUtil.encrypt(key, nonce, plaintext, aad);
        assertArrayEquals(expectedCt, actualCt, "AES-GCM ciphertext must match cross-language vector");
    }

    @Test
    public void testAesGcmDecryptVectorFile() throws Exception {
        Path vectorPath = VECTORS.resolve("aes_gcm/aes_gcm_vector.json");
        if (!vectorPath.toFile().exists()) return;

        Map<String, Object> data = loadJson(vectorPath);
        if (!data.containsKey("ciphertext_b64")) return;

        byte[] key = Base64.getDecoder().decode((String) data.get("key_b64"));
        byte[] nonce = Base64.getDecoder().decode((String) data.get("nonce_b64"));
        byte[] aad = Base64.getDecoder().decode((String) data.get("aad_b64"));
        byte[] expectedPt = Base64.getDecoder().decode((String) data.get("plaintext_b64"));
        byte[] ct = Base64.getDecoder().decode((String) data.get("ciphertext_b64"));

        byte[] actualPt = AesGcmUtil.decrypt(key, nonce, ct, aad);
        assertArrayEquals(expectedPt, actualPt, "AES-GCM decrypted plaintext must match");
    }

    @Test
    public void testDecryptWithWrongKeyFails() throws Exception {
        byte[] key = new byte[32];
        byte[] wrongKey = new byte[32];
        wrongKey[0] = 1;
        byte[] nonce = new byte[12];
        byte[] aad = "test".getBytes(StandardCharsets.UTF_8);
        byte[] plaintext = "data".getBytes(StandardCharsets.UTF_8);

        byte[] ciphertext = AesGcmUtil.encrypt(key, nonce, plaintext, aad);
        assertThrows(Exception.class, () -> AesGcmUtil.decrypt(wrongKey, nonce, ciphertext, aad));
    }
}
