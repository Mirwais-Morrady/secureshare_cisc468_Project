package com.cisc468share.protocol;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class SerializerTest {
    @Test
    void jsonRoundTrip() {
        Map<String, Object> input = new LinkedHashMap<>();
        input.put("type", "PING");
        input.put("version", "1.0");

        byte[] encoded = Serializer.jsonDumpsBytes(input);
        Map<String, Object> decoded = Serializer.jsonLoadsBytes(encoded);

        assertEquals("PING", decoded.get("type"));
        assertEquals("1.0", decoded.get("version"));
    }
}
