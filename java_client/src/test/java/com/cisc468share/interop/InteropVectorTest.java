package com.cisc468share.interop;

import com.cisc468share.crypto.HashUtil;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class InteropVectorTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void sha256VectorsMatch() throws Exception {
        Path path = Path.of("..", "shared_test_vectors", "hashes", "sha256_vectors.json");
        Map<String, Object> root = mapper.readValue(Files.readString(path), new TypeReference<Map<String, Object>>() {});
        List<Map<String, Object>> vectors = (List<Map<String, Object>>) root.get("vectors");

        for (Map<String, Object> item : vectors) {
            byte[] input = Base64.getDecoder().decode((String) item.get("input_b64"));
            byte[] expected = Base64.getDecoder().decode((String) item.get("sha256_b64"));
            byte[] actual = HashUtil.sha256Bytes(input);
            assertArrayEquals(expected, actual);
        }
    }

    @Test
    void hkdfVectorHasExpectedFields() throws Exception {
        Path path = Path.of("..", "shared_test_vectors", "hkdf", "hkdf_test_vectors.json");
        Map<String, Object> root = mapper.readValue(Files.readString(path), new TypeReference<Map<String, Object>>() {});
        assertTrue(root.containsKey("ikm_b64"));
        assertTrue(root.containsKey("salt_b64"));
        assertTrue(root.containsKey("info_b64"));
    }

    @Test
    void aesVectorHasExpectedFields() throws Exception {
        Path path = Path.of("..", "shared_test_vectors", "aes_gcm", "aes_gcm_vector.json");
        Map<String, Object> root = mapper.readValue(Files.readString(path), new TypeReference<Map<String, Object>>() {});
        assertTrue(root.containsKey("key_b64"));
        assertTrue(root.containsKey("nonce_b64"));
        assertTrue(root.containsKey("aad_b64"));
        assertTrue(root.containsKey("plaintext_b64"));
    }

    @Test
    void handshakeVectorHasExpectedFields() throws Exception {
        Path path = Path.of("..", "shared_test_vectors", "handshake", "handshake_vector.json");
        Map<String, Object> root = mapper.readValue(Files.readString(path), new TypeReference<Map<String, Object>>() {});
        assertTrue(root.containsKey("client_nonce_b64"));
        assertTrue(root.containsKey("server_nonce_b64"));
        assertTrue(root.containsKey("client_dh_public_b64"));
        assertTrue(root.containsKey("server_dh_public_b64"));
    }

    @Test
    void manifestVectorHasExpectedFields() throws Exception {
        Path path = Path.of("..", "shared_test_vectors", "manifests", "manifest_vector.json");
        Map<String, Object> root = mapper.readValue(Files.readString(path), new TypeReference<Map<String, Object>>() {});
        assertTrue(root.containsKey("filename"));
        assertTrue(root.containsKey("size"));
        assertTrue(root.containsKey("sha256_b64"));
        assertTrue(root.containsKey("signature_b64"));
    }
}
