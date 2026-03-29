package com.cisc468share.storage;

import com.cisc468share.protocol.CanonicalJson;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * JSON-backed manifest storage keyed by filename.
 * Persists to data/manifests.json.
 */
public class ManifestStore {

    private final Path path;
    private final ObjectMapper mapper = CanonicalJson.mapper();

    public ManifestStore(Path path) {
        this.path = path;
    }

    private Map<String, Map<String, Object>> loadAll() {
        if (!Files.exists(path)) return new LinkedHashMap<>();
        try {
            return mapper.readValue(path.toFile(),
                    new TypeReference<Map<String, Map<String, Object>>>() {});
        } catch (Exception e) {
            return new LinkedHashMap<>();
        }
    }

    /** Save a manifest keyed by its file_name field. */
    public void save(Map<String, Object> manifest) {
        String filename = (String) manifest.get("file_name");
        if (filename == null) return;
        Map<String, Map<String, Object>> all = loadAll();
        all.put(filename, manifest);
        write(all);
    }

    /** Retrieve manifest for a filename, or null if not found. */
    public Map<String, Object> get(String filename) {
        return loadAll().get(filename);
    }

    /** Return all stored manifests. */
    public Map<String, Map<String, Object>> listAll() {
        return loadAll();
    }

    private void write(Map<String, Map<String, Object>> data) {
        try {
            Files.createDirectories(path.getParent());
            mapper.writerWithDefaultPrettyPrinter().writeValue(path.toFile(), data);
        } catch (Exception e) {
            System.out.println("[ERROR] Failed to write manifest store: " + e.getMessage());
        }
    }
}
