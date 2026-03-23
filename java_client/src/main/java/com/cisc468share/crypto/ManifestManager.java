package com.cisc468share.crypto;

import com.cisc468share.protocol.CanonicalJson;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Manages file manifests for integrity verification.
 */
public class ManifestManager {

    public static Map<String, Object> buildManifest(String peerId, String peerName, Path filePath) throws Exception {
        File file = filePath.toFile();
        long size = file.length();
        String sha256hex = sha256FileHex(filePath);

        Map<String, Object> manifest = new LinkedHashMap<>();
        manifest.put("manifest_version", "1.0");
        manifest.put("owner_peer_id", peerId);
        manifest.put("owner_peer_name", peerName);
        manifest.put("file_name", filePath.getFileName().toString());
        manifest.put("file_size", size);
        manifest.put("file_sha256_hex", sha256hex);
        return manifest;
    }

    public static Map<String, Object> signManifest(PrivateKey privateKey, Map<String, Object> manifest) throws Exception {
        byte[] data = CanonicalJson.toBytes(manifest);
        byte[] sig = IdentityManager.sign(privateKey, data);

        Map<String, Object> signed = new LinkedHashMap<>(manifest);
        signed.put("signature_b64", Base64.getEncoder().encodeToString(sig));
        return signed;
    }

    public static boolean verifyManifest(PublicKey publicKey, Map<String, Object> manifest) throws Exception {
        Map<String, Object> unsigned = new LinkedHashMap<>(manifest);
        String sigB64 = (String) unsigned.remove("signature_b64");
        if (sigB64 == null) return false;

        byte[] data = CanonicalJson.toBytes(unsigned);
        byte[] sig = Base64.getDecoder().decode(sigB64);
        return IdentityManager.verify(publicKey, data, sig);
    }

    private static String sha256FileHex(Path path) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try (FileInputStream fis = new FileInputStream(path.toFile())) {
            byte[] buf = new byte[65536];
            int n;
            while ((n = fis.read(buf)) != -1) {
                md.update(buf, 0, n);
            }
        }
        return HashUtil.toHex(md.digest());
    }
}
