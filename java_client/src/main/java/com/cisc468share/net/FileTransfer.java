package com.cisc468share.net;

import com.cisc468share.files.Chunker;

import java.io.File;
import java.nio.file.Files;
import java.util.List;

public class FileTransfer {

    public static List<byte[]> chunkFile(File file) throws Exception {

        byte[] data = Files.readAllBytes(file.toPath());

        return Chunker.chunkBytes(data);

    }
}
