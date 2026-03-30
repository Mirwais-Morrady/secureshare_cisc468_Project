package com.cisc468share.storage;

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
 * Manages persistent share index storage.
 */
public class ShareIndexStore {
    private final Path indexPath;
    private final ObjectMapper mapper = CanonicalJson.mapper();
    
    public ShareIndexStore(Path indexPath) {
        this.indexPath = indexPath;
    }
    
    /**
     * Add a share to the index.
     * 
     * @param shareId The share identifier
     * @param shareInfo Information about the share
     */
    public void addShare(String shareId, java.util.Map<String, Object> shareInfo) {
        Map<String, Map<String, Object>> all = loadAll();
        all.put(shareId, new LinkedHashMap<>(shareInfo));
        saveAll(all);
    }
    
    /**
     * Get share information.
     * 
     * @param shareId The share identifier
     * @return The share information
     */
    public java.util.Map<String, Object> getShare(String shareId) {
        return loadAll().get(shareId);
    }
    
    /**
     * List all shares.
     * 
     * @return List of share IDs
     */
    public java.util.List<String> listShares() {
        return new ArrayList<>(loadAll().keySet());
    }
    
    /**
     * Remove a share from the index.
     * 
     * @param shareId The share identifier
     */
    public void removeShare(String shareId) {
        Map<String, Map<String, Object>> all = loadAll();
        all.remove(shareId);
        saveAll(all);
    }

    private Map<String, Map<String, Object>> loadAll() {
        if (!Files.exists(indexPath)) {
            return new LinkedHashMap<>();
        }
        try {
            return mapper.readValue(indexPath.toFile(), new TypeReference<Map<String, Map<String, Object>>>() {});
        } catch (Exception e) {
            return new LinkedHashMap<>();
        }
    }

    private void saveAll(Map<String, Map<String, Object>> data) {
        try {
            Files.createDirectories(indexPath.getParent());
            mapper.writerWithDefaultPrettyPrinter().writeValue(indexPath.toFile(), data);
        } catch (Exception e) {
            throw new RuntimeException("Failed to write share index", e);
        }
    }
}
