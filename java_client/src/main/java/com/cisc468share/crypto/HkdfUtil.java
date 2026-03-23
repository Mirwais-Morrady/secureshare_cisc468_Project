package com.cisc468share.crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

public final class HkdfUtil {
    private HkdfUtil() {}

    public static byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length) {
        byte[] prk = hmacSha256(salt, ikm);
        return hkdfExpand(prk, info, length);
    }

    public static Map<String, byte[]> deriveSessionMaterial(byte[] sharedSecret, byte[] transcriptHash) {
        Map<String, byte[]> out = new LinkedHashMap<>();
        out.put("client_to_server_key", hkdfSha256(
                sharedSecret, transcriptHash,
                "cisc468/session/client_to_server".getBytes(StandardCharsets.UTF_8), 32));
        out.put("server_to_client_key", hkdfSha256(
                sharedSecret, transcriptHash,
                "cisc468/session/server_to_client".getBytes(StandardCharsets.UTF_8), 32));
        out.put("session_id_material", hkdfSha256(
                sharedSecret, transcriptHash,
                "cisc468/session/session_id".getBytes(StandardCharsets.UTF_8), 16));
        return out;
    }

    private static byte[] hkdfExpand(byte[] prk, byte[] info, int length) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] previous = new byte[0];
            int counter = 1;
            while (out.size() < length) {
                ByteArrayOutputStream input = new ByteArrayOutputStream();
                input.write(previous);
                input.write(info);
                input.write(counter);
                previous = hmacSha256(prk, input.toByteArray());
                out.write(previous);
                counter++;
            }
            byte[] okm = out.toByteArray();
            byte[] result = new byte[length];
            System.arraycopy(okm, 0, result, 0, length);
            return result;
        } catch (Exception e) {
            throw new IllegalStateException("HKDF expand failed", e);
        }
    }

    private static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new IllegalStateException("HMAC-SHA256 failed", e);
        }
    }
}
