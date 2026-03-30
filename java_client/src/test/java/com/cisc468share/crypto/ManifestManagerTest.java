package com.cisc468share.crypto;

import com.cisc468share.protocol.CanonicalJson;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * REQUIREMENT 5 — Offline Redistribution with Tamper Verification (Java)
 *
 * Verifies that:
 * - Manifest contains required fields including SHA-256 of the file
 * - Manifest is signed with RSA-PSS-SHA-256
 * - Signature verifies with the owner's public key
 * - A tampered manifest is rejected
 * - A manifest signed by a different key is rejected
 * - Tampered file detected via SHA-256 mismatch
 */
public class ManifestManagerTest {

    @Test
    public void testManifestContainsRequiredFields(@TempDir Path tmp) throws Exception {
        KeyPair kp = IdentityManager.generateRSA();
        byte[] pubDer = kp.getPublic().getEncoded();
        String peerId = IdentityManager.fingerprint(pubDer);

        Path file = tmp.resolve("report.txt");
        Files.write(file, "Annual financial report data".getBytes());

        Map<String, Object> manifest = ManifestManager.buildManifest(peerId, "alice", file);

        assertEquals("1.0", manifest.get("manifest_version"));
        assertEquals(peerId, manifest.get("owner_peer_id"));
        assertEquals("alice", manifest.get("owner_peer_name"));
        assertEquals("report.txt", manifest.get("file_name"));
        assertNotNull(manifest.get("file_sha256_hex"), "SHA-256 must be present");
        assertNotNull(manifest.get("file_size"), "File size must be present");
    }

    @Test
    public void testManifestSha256MatchesFile(@TempDir Path tmp) throws Exception {
        KeyPair kp = IdentityManager.generateRSA();
        String peerId = IdentityManager.fingerprint(kp.getPublic().getEncoded());
        byte[] content = "File content for integrity test".getBytes();
        Path file = tmp.resolve("data.bin");
        Files.write(file, content);

        Map<String, Object> manifest = ManifestManager.buildManifest(peerId, "peer", file);

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        String expected = HashUtil.toHex(md.digest(content));
        assertEquals(expected, manifest.get("file_sha256_hex"),
                "Manifest SHA-256 must match the actual file content");
    }

    @Test
    public void testSignedManifestVerifies(@TempDir Path tmp) throws Exception {
        KeyPair kp = IdentityManager.generateRSA();
        String peerId = IdentityManager.fingerprint(kp.getPublic().getEncoded());
        Path file = tmp.resolve("f.txt");
        Files.write(file, "file content here".getBytes());

        Map<String, Object> manifest = ManifestManager.buildManifest(peerId, "peer", file);
        Map<String, Object> signed = ManifestManager.signManifest(kp.getPrivate(), manifest);

        assertTrue(ManifestManager.verifyManifest(kp.getPublic(), signed),
                "Signed manifest must verify against owner's public key");
    }

    @Test
    public void testTamperedManifestRejected(@TempDir Path tmp) throws Exception {
        KeyPair kp = IdentityManager.generateRSA();
        String peerId = IdentityManager.fingerprint(kp.getPublic().getEncoded());
        Path file = tmp.resolve("f.txt");
        Files.write(file, "content".getBytes());

        Map<String, Object> manifest = ManifestManager.buildManifest(peerId, "peer", file);
        Map<String, Object> signed = ManifestManager.signManifest(kp.getPrivate(), new LinkedHashMap<>(manifest));

        // Attacker modifies file size after signing
        signed.put("file_size", 0L);
        assertFalse(ManifestManager.verifyManifest(kp.getPublic(), signed),
                "Tampered manifest must NOT verify");
    }

    @Test
    public void testManifestFromWrongKeyRejected(@TempDir Path tmp) throws Exception {
        KeyPair ownerKp = IdentityManager.generateRSA();
        KeyPair attackerKp = IdentityManager.generateRSA();
        String ownerId = IdentityManager.fingerprint(ownerKp.getPublic().getEncoded());
        Path file = tmp.resolve("f.txt");
        Files.write(file, "content".getBytes());

        Map<String, Object> manifest = ManifestManager.buildManifest(ownerId, "owner", file);
        // Attacker signs with their own key
        Map<String, Object> attackerSigned = ManifestManager.signManifest(
                attackerKp.getPrivate(), new LinkedHashMap<>(manifest));

        // Verify against the OWNER's public key — must fail
        assertFalse(ManifestManager.verifyManifest(ownerKp.getPublic(), attackerSigned),
                "Manifest signed by wrong key must not verify against owner's key");
    }

    @Test
    public void testTamperedFileDetectedViaSha256(@TempDir Path tmp) throws Exception {
        KeyPair kp = IdentityManager.generateRSA();
        String peerId = IdentityManager.fingerprint(kp.getPublic().getEncoded());
        byte[] originalContent = "Original file data".getBytes();
        Path file = tmp.resolve("original.txt");
        Files.write(file, originalContent);

        Map<String, Object> manifest = ManifestManager.buildManifest(peerId, "peer", file);
        String manifestHash = (String) manifest.get("file_sha256_hex");

        // Simulate receiving a tampered file
        byte[] tampered = "Tampered file data!!".getBytes();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        String receivedHash = HashUtil.toHex(md.digest(tampered));

        assertNotEquals(manifestHash, receivedHash,
                "Tampered file SHA-256 must differ from manifest SHA-256");
    }
}
