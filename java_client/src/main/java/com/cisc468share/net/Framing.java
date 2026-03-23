package com.cisc468share.net;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

public final class Framing {
    public static final int MAX_FRAME_SIZE = 16 * 1024 * 1024;

    private Framing() {}

    public static byte[] encodeFrame(byte[] payload) {
        if (payload.length > MAX_FRAME_SIZE) {
            throw new IllegalArgumentException("Payload exceeds maximum frame size");
        }
        ByteBuffer buffer = ByteBuffer.allocate(4 + payload.length);
        buffer.putInt(payload.length);
        buffer.put(payload);
        return buffer.array();
    }

    public static byte[] decodeFrame(InputStream inputStream) throws IOException {
        byte[] header = readExact(inputStream, 4);
        int length = ByteBuffer.wrap(header).getInt();
        if (length < 0 || length > MAX_FRAME_SIZE) {
            throw new IOException("Invalid frame size");
        }
        return readExact(inputStream, length);
    }

    private static byte[] readExact(InputStream inputStream, int size) throws IOException {
        byte[] data = new byte[size];
        int offset = 0;
        while (offset < size) {
            int read = inputStream.read(data, offset, size - offset);
            if (read == -1) {
                throw new IOException("Unexpected EOF");
            }
            offset += read;
        }
        return data;
    }
}
