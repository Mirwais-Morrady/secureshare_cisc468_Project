package com.cisc468share.storage;

import com.cisc468share.protocol.CanonicalJson;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * JSON-backed contacts storage keyed by peer_id.
 * Persists to data/contacts.json.
 */
public class ContactsStore {

    private final Path path;
    private final ObjectMapper mapper = CanonicalJson.mapper();

    public ContactsStore(Path path) {
        this.path = path;
    }

    /** Load all contacts from disk. */
    public Map<String, Map<String, Object>> load() {
        if (!Files.exists(path)) return new LinkedHashMap<>();
        try {
            return mapper.readValue(path.toFile(),
                    new TypeReference<Map<String, Map<String, Object>>>() {});
        } catch (Exception e) {
            return new LinkedHashMap<>();
        }
    }

    /** Save the full contacts map to disk. */
    public void save(Map<String, Map<String, Object>> contacts) {
        try {
            Files.createDirectories(path.getParent());
            mapper.writerWithDefaultPrettyPrinter().writeValue(path.toFile(), contacts);
        } catch (Exception e) {
            System.out.println("[ERROR] Failed to save contacts: " + e.getMessage());
        }
    }

    /** Get a single contact by peer_id, or null. */
    public Map<String, Object> get(String peerId) {
        return load().get(peerId);
    }

    /** Add or update a single contact entry. */
    public void add(String peerId, Map<String, Object> info) {
        Map<String, Map<String, Object>> all = load();
        all.put(peerId, info);
        save(all);
    }

    /** Remove a contact entry. */
    public void remove(String peerId) {
        Map<String, Map<String, Object>> all = load();
        all.remove(peerId);
        save(all);
    }
}
