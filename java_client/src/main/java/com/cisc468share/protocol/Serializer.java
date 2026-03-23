package com.cisc468share.protocol;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.util.Map;

public final class Serializer {
    private static final ObjectMapper MAPPER = CanonicalJson.mapper();

    private Serializer() {}

    public static byte[] jsonDumpsBytes(Object value) {
        try {
            return MAPPER.writeValueAsString(value).getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to serialize JSON", e);
        }
    }

    public static Map<String, Object> jsonLoadsBytes(byte[] data) {
        try {
            return MAPPER.readValue(data, new TypeReference<Map<String, Object>>() {});
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse JSON", e);
        }
    }
}
