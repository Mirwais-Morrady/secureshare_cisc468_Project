package com.cisc468share.protocol;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.nio.charset.StandardCharsets;

public final class CanonicalJson {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    static {
        MAPPER.configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true);
        MAPPER.configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);
    }

    private CanonicalJson() {}

    public static byte[] toBytes(Object value) {
        try {
            return MAPPER.writeValueAsString(value).getBytes(StandardCharsets.UTF_8);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Failed to serialize canonical JSON", e);
        }
    }

    public static String toText(Object value) {
        return new String(toBytes(value), StandardCharsets.UTF_8);
    }

    public static ObjectMapper mapper() {
        return MAPPER;
    }
}
