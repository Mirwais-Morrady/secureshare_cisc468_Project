package com.cisc468share.protocol;

import com.cisc468share.net.Framing;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class FramingTest {
    @Test
    void roundTripFrame() throws Exception {
        byte[] payload = "hello".getBytes(StandardCharsets.UTF_8);
        byte[] frame = Framing.encodeFrame(payload);
        byte[] decoded = Framing.decodeFrame(new ByteArrayInputStream(frame));
        assertArrayEquals(payload, decoded);
    }
}
