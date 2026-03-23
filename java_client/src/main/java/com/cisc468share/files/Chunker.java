package com.cisc468share.files;

import java.util.ArrayList;
import java.util.List;

/**
 * Handles file chunking for efficient transfer.
 */
public class Chunker {

    public static final int CHUNK_SIZE = 65536;

    public static List<byte[]> chunkBytes(byte[] data) {
        List<byte[]> chunks = new ArrayList<>();
        int offset = 0;
        while (offset < data.length) {
            int end = Math.min(offset + CHUNK_SIZE, data.length);
            byte[] chunk = new byte[end - offset];
            System.arraycopy(data, offset, chunk, 0, chunk.length);
            chunks.add(chunk);
            offset = end;
        }
        return chunks;
    }
}
