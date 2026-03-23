package com.cisc468share.files;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Manages file sharing operations.
 */
public class ShareManager {

    private final Path sharedDir;

    public ShareManager(Path sharedDir) {
        this.sharedDir = sharedDir;
        try {
            Files.createDirectories(sharedDir);
        } catch (Exception e) {
            throw new RuntimeException("Failed to create shared directory", e);
        }
    }

    public List<String> listFiles() {
        List<String> names = new ArrayList<>();
        File[] files = sharedDir.toFile().listFiles();
        if (files != null) {
            for (File f : files) {
                if (f.isFile()) {
                    names.add(f.getName());
                }
            }
        }
        return names;
    }

    public Path getFilePath(String filename) {
        return sharedDir.resolve(filename);
    }

    public boolean hasFile(String filename) {
        return sharedDir.resolve(filename).toFile().isFile();
    }

    public Path getSharedDir() {
        return sharedDir;
    }
}
