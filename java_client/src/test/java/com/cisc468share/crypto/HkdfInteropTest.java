package com.cisc468share.crypto;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;

import static org.junit.jupiter.api.Assertions.*;

public class HkdfInteropTest {

    private static final Path VECTORS = Paths.get(
            System.getProperty("project.root", "../../.."),
            "shared_test_vectors"
    );

    @SuppressWarnings("unchecked")
    @Test
    public void testHkdfOkmVector() throws Exception {
        Path vectorPath = VECTORS.resolve("hkdf/hkdf_test_vectors.json");
        if (!vectorPath.toFile().exists()) return;

        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object> data = mapper.readValue(Files.readString(vectorPath), Map.class);

        if (!data.containsKey("okm_b64")) return;

        byte[] ikm = Base64.getDecoder().decode((String) data.get("ikm_b64"));
        byte[] salt = Base64.getDecoder().decode((String) data.get("salt_b64"));
        byte[] info = Base64.getDecoder().decode((String) data.get("info_b64"));
        byte[] expectedOkm = Base64.getDecoder().decode((String) data.get("okm_b64"));
        int length = ((Number) data.get("length")).intValue();

        byte[] actualOkm = HkdfUtil.hkdfSha256(ikm, salt, info, length);
        assertArrayEquals(expectedOkm, actualOkm, "HKDF OKM must match cross-language vector");
    }

    @Test
    public void testHkdfDeterministic() {
        byte[] ikm = "input-key-material".getBytes(StandardCharsets.UTF_8);
        byte[] salt = "salt".getBytes(StandardCharsets.UTF_8);
        byte[] info = "context-info".getBytes(StandardCharsets.UTF_8);

        byte[] okm1 = HkdfUtil.hkdfSha256(ikm, salt, info, 32);
        byte[] okm2 = HkdfUtil.hkdfSha256(ikm, salt, info, 32);
        assertArrayEquals(okm1, okm2, "HKDF must be deterministic");
        assertEquals(32, okm1.length);
    }

    @Test
    public void testHkdfDifferentInfoProducesDifferentOutput() {
        byte[] ikm = "ikm".getBytes(StandardCharsets.UTF_8);
        byte[] salt = "salt".getBytes(StandardCharsets.UTF_8);

        byte[] okm1 = HkdfUtil.hkdfSha256(ikm, salt, "info1".getBytes(StandardCharsets.UTF_8), 32);
        byte[] okm2 = HkdfUtil.hkdfSha256(ikm, salt, "info2".getBytes(StandardCharsets.UTF_8), 32);
        assertFalse(Arrays.equals(okm1, okm2));
    }
}
