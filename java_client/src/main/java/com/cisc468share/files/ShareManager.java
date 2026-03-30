package com.cisc468share.files;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import com.cisc468share.storage.ShareIndexStore;
import com.cisc468share.storage.VaultStore;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Manages file sharing operations.
 */
public class ShareManager {

    private final Path sharedDir;
    private final VaultStore sharedVaultStore;
    private final ShareIndexStore shareIndexStore;

    public ShareManager(Path sharedDir, VaultStore sharedVaultStore, ShareIndexStore shareIndexStore) {
        this.sharedDir = sharedDir;
        this.sharedVaultStore = sharedVaultStore;
        this.shareIndexStore = shareIndexStore;
        try {
            Files.createDirectories(sharedDir);
            migratePlaintextShares();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create shared directory", e);
        }
    }

    public List<String> listFiles() {
        return shareIndexStore.listShares();
    }

    public Path getFilePath(String filename) {
        return sharedDir.resolve(filename);
    }

    public boolean hasFile(String filename) {
        return shareIndexStore.getShare(filename) != null;
    }

    public void addFile(Path source) throws Exception {
        String filename = source.getFileName().toString();
        sharedVaultStore.storeFile(filename, Files.readAllBytes(source));
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("stored_in", "shared_vault");
        shareIndexStore.addShare(filename, info);
        Files.deleteIfExists(sharedDir.resolve(filename));
    }

    public byte[] getFileBytes(String filename) {
        if (!hasFile(filename)) {
            throw new RuntimeException("Shared file not found: " + filename);
        }
        return sharedVaultStore.getFile(filename);
    }

    public long getFileSize(String filename) {
        return getFileBytes(filename).length;
    }

    public Path getSharedDir() {
        return sharedDir;
    }

    private void migratePlaintextShares() throws Exception {
        if (!Files.exists(sharedDir)) {
            return;
        }

        try (var paths = Files.list(sharedDir)) {
            paths.filter(Files::isRegularFile).forEach(path -> {
                try {
                    String filename = path.getFileName().toString();
                    sharedVaultStore.storeFile(filename, Files.readAllBytes(path));
                    Map<String, Object> info = new LinkedHashMap<>();
                    info.put("stored_in", "shared_vault");
                    shareIndexStore.addShare(filename, info);
                    Files.deleteIfExists(path);
                } catch (Exception e) {
                    throw new RuntimeException("Failed to migrate shared file", e);
                }
            });
        }
    }
}
