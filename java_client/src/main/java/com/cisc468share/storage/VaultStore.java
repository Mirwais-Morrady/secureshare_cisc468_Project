package com.cisc468share.storage;

import com.cisc468share.crypto.Vault;
import com.cisc468share.protocol.CanonicalJson;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Manages persistent vault storage.
 */
public class VaultStore {
    private final Path vaultPath;
    private final String password;
    private final Path indexPath;
    private final ObjectMapper mapper = CanonicalJson.mapper();

    public VaultStore(Path vaultPath, String password) {
        this.vaultPath = vaultPath;
        this.password = password;
        this.indexPath = vaultPath.resolve("index.json");
        try {
            Files.createDirectories(vaultPath);
        } catch (Exception e) {
            throw new RuntimeException("Failed to create vault directory", e);
        }
    }
    
    /**
     * Store an encrypted file.
     * 
     * @param fileId The file identifier
     * @param encryptedData The encrypted file data
     */
    public void storeEncryptedFile(String fileId, byte[] encryptedData) {
        try {
            Files.write(encryptedPath(fileId), encryptedData);
            updateIndex(fileId, fileId + ".enc");
        } catch (Exception e) {
            throw new RuntimeException("Failed to store encrypted file", e);
        }
    }
    
    /**
     * Retrieve an encrypted file.
     * 
     * @param fileId The file identifier
     * @return The encrypted file data
     */
    public byte[] retrieveEncryptedFile(String fileId) {
        try {
            return Files.readAllBytes(encryptedPath(fileId));
        } catch (Exception e) {
            throw new RuntimeException("Failed to read encrypted file", e);
        }
    }
    
    /**
     * Delete a file from the vault.
     * 
     * @param fileId The file identifier
     */
    public void deleteFile(String fileId) {
        try {
            Files.deleteIfExists(encryptedPath(fileId));
            Map<String, String> index = loadIndex();
            index.remove(fileId);
            saveIndex(index);
        } catch (Exception e) {
            throw new RuntimeException("Failed to delete vault file", e);
        }
    }
    
    /**
     * List all files in the vault.
     * 
     * @return List of file IDs
     */
    public java.util.List<String> listFiles() {
        return new ArrayList<>(loadIndex().keySet());
    }

    public void storeFile(String fileId, byte[] data) {
        try {
            storeEncryptedFile(fileId, Vault.encryptVault(password, data));
        } catch (Exception e) {
            throw new RuntimeException("Failed to encrypt vault file", e);
        }
    }

    public byte[] getFile(String fileId) {
        try {
            return Vault.decryptVault(password, retrieveEncryptedFile(fileId));
        } catch (Exception e) {
            throw new RuntimeException("Failed to decrypt vault file", e);
        }
    }

    private Path encryptedPath(String fileId) {
        return vaultPath.resolve(fileId + ".enc");
    }

    private Map<String, String> loadIndex() {
        if (!Files.exists(indexPath)) {
            return new LinkedHashMap<>();
        }

        try {
            return mapper.readValue(indexPath.toFile(), new TypeReference<Map<String, String>>() {});
        } catch (Exception e) {
            return new LinkedHashMap<>();
        }
    }

    private void saveIndex(Map<String, String> index) {
        try {
            mapper.writerWithDefaultPrettyPrinter().writeValue(indexPath.toFile(), index);
        } catch (Exception e) {
            throw new RuntimeException("Failed to write vault index", e);
        }
    }

    private void updateIndex(String fileId, String encryptedName) {
        Map<String, String> index = loadIndex();
        index.put(fileId, encryptedName);
        saveIndex(index);
    }
}
