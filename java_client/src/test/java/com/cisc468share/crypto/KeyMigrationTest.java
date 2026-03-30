package com.cisc468share.crypto;

import com.cisc468share.protocol.CanonicalJson;
import com.cisc468share.storage.ContactsStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.security.KeyPair;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * REQUIREMENT 6 — Key Migration (Java)
 *
 * Verifies that:
 * - A KEY_MIGRATION message contains all required fields
 * - The old-key signature is verifiable with the old public key
 * - applyMigrationMessage accepts a properly signed migration from a known contact
 * - applyMigrationMessage rejects a migration from an unknown (untrusted) sender
 * - A tampered migration message is rejected
 * - After migration the contacts store holds the new peer ID / public key
 */
public class KeyMigrationTest {

    /** Build a KEY_MIGRATION message the same way cmdRotateKey() does. */
    private Map<String, Object> buildMigration(
            String oldId, KeyPair oldKp, String newId, KeyPair newKp, String peerName) throws Exception {

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("type",                        "KEY_MIGRATION");
        body.put("proto_ver",                   "1.0");
        body.put("old_peer_id",                 oldId);
        body.put("new_peer_id",                 newId);
        body.put("new_peer_name",               peerName);
        body.put("new_rsa_public_key_der_b64",  Base64.getEncoder().encodeToString(newKp.getPublic().getEncoded()));

        byte[] oldSig = IdentityManager.sign(oldKp.getPrivate(), CanonicalJson.toBytes(body));
        body.put("old_key_signature_b64", Base64.getEncoder().encodeToString(oldSig));

        Map<String, Object> bodyForNewSig = new LinkedHashMap<>(body);
        bodyForNewSig.remove("old_key_signature_b64");
        byte[] newSig = IdentityManager.sign(newKp.getPrivate(), CanonicalJson.toBytes(bodyForNewSig));
        body.put("new_key_signature_b64", Base64.getEncoder().encodeToString(newSig));

        return body;
    }

    /** Create a ContactsStore at the given path with one pre-registered contact. */
    private ContactsStore storeWithContact(Path dir, String peerId, byte[] pubDer) {
        ContactsStore cs = new ContactsStore(dir.resolve("contacts.json"));
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("peer_name",               "known-peer");
        info.put("rsa_public_key_der_b64",  Base64.getEncoder().encodeToString(pubDer));
        cs.add(peerId, info);
        return cs;
    }

    @Test
    public void testMigrationMessageContainsRequiredFields(@TempDir Path tmp) throws Exception {
        KeyPair oldKp = IdentityManager.generateRSA();
        KeyPair newKp = IdentityManager.generateRSA();
        String oldId = IdentityManager.fingerprint(oldKp.getPublic().getEncoded());
        String newId = IdentityManager.fingerprint(newKp.getPublic().getEncoded());

        Map<String, Object> msg = buildMigration(oldId, oldKp, newId, newKp, "alice");

        assertEquals("KEY_MIGRATION", msg.get("type"));
        assertEquals("1.0", msg.get("proto_ver"));
        assertEquals(oldId, msg.get("old_peer_id"));
        assertEquals(newId, msg.get("new_peer_id"));
        assertNotNull(msg.get("new_rsa_public_key_der_b64"), "New public key must be embedded");
        assertNotNull(msg.get("old_key_signature_b64"),      "Old-key signature must be present");
        assertNotNull(msg.get("new_key_signature_b64"),      "New-key signature must be present");
    }

    @Test
    public void testOldAndNewPeerIdsDiffer(@TempDir Path tmp) throws Exception {
        KeyPair oldKp = IdentityManager.generateRSA();
        KeyPair newKp = IdentityManager.generateRSA();
        String oldId = IdentityManager.fingerprint(oldKp.getPublic().getEncoded());
        String newId = IdentityManager.fingerprint(newKp.getPublic().getEncoded());
        Map<String, Object> msg = buildMigration(oldId, oldKp, newId, newKp, "bob");
        assertNotEquals(msg.get("old_peer_id"), msg.get("new_peer_id"),
                "Old and new peer IDs must differ (distinct RSA key pairs)");
    }

    @Test
    public void testOldKeySignatureIsVerifiable(@TempDir Path tmp) throws Exception {
        KeyPair oldKp = IdentityManager.generateRSA();
        KeyPair newKp = IdentityManager.generateRSA();
        String oldId = IdentityManager.fingerprint(oldKp.getPublic().getEncoded());
        String newId = IdentityManager.fingerprint(newKp.getPublic().getEncoded());
        Map<String, Object> msg = buildMigration(oldId, oldKp, newId, newKp, "carol");

        // Reproduce what applyMigrationMessage does: verify old signature over body without sigs
        Map<String, Object> body = new LinkedHashMap<>(msg);
        body.remove("old_key_signature_b64");
        body.remove("new_key_signature_b64");
        byte[] sig = Base64.getDecoder().decode((String) msg.get("old_key_signature_b64"));
        assertTrue(IdentityManager.verify(oldKp.getPublic(), CanonicalJson.toBytes(body), sig),
                "Old-key signature must verify with old public key");
    }

    @Test
    public void testApplyMigrationFromKnownContact(@TempDir Path tmp) throws Exception {
        KeyPair oldKp = IdentityManager.generateRSA();
        KeyPair newKp = IdentityManager.generateRSA();
        String oldId = IdentityManager.fingerprint(oldKp.getPublic().getEncoded());
        String newId = IdentityManager.fingerprint(newKp.getPublic().getEncoded());

        ContactsStore cs = storeWithContact(tmp, oldId, oldKp.getPublic().getEncoded());
        Map<String, Object> msg = buildMigration(oldId, oldKp, newId, newKp, "dave");

        boolean result = KeyMigrationUtil.applyMigrationMessage(msg, cs);

        assertTrue(result, "Migration from known contact must be accepted");
        // Old ID removed, new ID added
        assertNull(cs.get(oldId),  "Old peer ID must be removed from contacts");
        assertNotNull(cs.get(newId), "New peer ID must be added to contacts");
    }

    @Test
    public void testApplyMigrationFromUnknownSenderRejected(@TempDir Path tmp) throws Exception {
        KeyPair unknownKp = IdentityManager.generateRSA();
        KeyPair newKp     = IdentityManager.generateRSA();
        String unknownId  = IdentityManager.fingerprint(unknownKp.getPublic().getEncoded());
        String newId      = IdentityManager.fingerprint(newKp.getPublic().getEncoded());

        // ContactsStore is empty — sender is unknown
        ContactsStore cs = new ContactsStore(tmp.resolve("empty_contacts.json"));
        Map<String, Object> msg = buildMigration(unknownId, unknownKp, newId, newKp, "eve");

        boolean result = KeyMigrationUtil.applyMigrationMessage(msg, cs);
        assertFalse(result, "Migration from unknown sender must be rejected");
    }

    @Test
    public void testTamperedMigrationRejected(@TempDir Path tmp) throws Exception {
        KeyPair oldKp = IdentityManager.generateRSA();
        KeyPair newKp = IdentityManager.generateRSA();
        String oldId = IdentityManager.fingerprint(oldKp.getPublic().getEncoded());
        String newId = IdentityManager.fingerprint(newKp.getPublic().getEncoded());

        ContactsStore cs = storeWithContact(tmp, oldId, oldKp.getPublic().getEncoded());
        Map<String, Object> msg = buildMigration(oldId, oldKp, newId, newKp, "frank");

        // Attacker modifies a field after signing
        msg.put("new_peer_name", "attacker-controlled-name");

        boolean result = KeyMigrationUtil.applyMigrationMessage(msg, cs);
        assertFalse(result, "Tampered migration message must be rejected");
    }
}
