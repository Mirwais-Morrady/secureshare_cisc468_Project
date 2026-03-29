package com.cisc468share.crypto;

import com.cisc468share.protocol.CanonicalJson;
import com.cisc468share.storage.ContactsStore;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

public final class KeyMigrationUtil {
    private KeyMigrationUtil() {}

    public static boolean applyMigrationMessage(Map<String, Object> msg, ContactsStore contactsStore) {
        if (contactsStore == null) {
            System.out.println("[WARNING] Key migration received but no contacts store available");
            return false;
        }

        String oldPeerId = (String) msg.getOrDefault("old_peer_id", "");
        String newPeerId = (String) msg.getOrDefault("new_peer_id", "");
        String newPeerName = (String) msg.getOrDefault("new_peer_name", "unknown");
        String newPubB64 = (String) msg.get("new_rsa_public_key_der_b64");

        Map<String, Map<String, Object>> contacts = contactsStore.load();
        Map<String, Object> oldContact = contacts.get(oldPeerId);

        if (oldContact == null) {
            System.out.println("[SECURITY WARNING] Key migration from unknown peer: "
                    + oldPeerId.substring(0, Math.min(16, oldPeerId.length())) + "...");
            return false;
        }

        try {
            byte[] oldPubDer = Base64.getDecoder().decode((String) oldContact.get("rsa_public_key_der_b64"));
            PublicKey oldPubKey = KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(oldPubDer));

            byte[] newPubDer = Base64.getDecoder().decode(newPubB64);
            PublicKey newPubKey = KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(newPubDer));

            Map<String, Object> signedByOld = new LinkedHashMap<>(msg);
            signedByOld.remove("old_key_signature_b64");
            signedByOld.remove("new_key_signature_b64");
            byte[] canonicalBody = CanonicalJson.toBytes(signedByOld);

            byte[] oldSig = Base64.getDecoder().decode((String) msg.get("old_key_signature_b64"));
            if (!IdentityManager.verify(oldPubKey, canonicalBody, oldSig)) {
                throw new SecurityException("old-key signature verification failed");
            }

            Map<String, Object> signedByNew = new LinkedHashMap<>(msg);
            signedByNew.remove("old_key_signature_b64");
            signedByNew.remove("new_key_signature_b64");
            byte[] canonicalWithNewBody = CanonicalJson.toBytes(signedByNew);

            byte[] newSig = Base64.getDecoder().decode((String) msg.get("new_key_signature_b64"));
            if (!IdentityManager.verify(newPubKey, canonicalWithNewBody, newSig)) {
                throw new SecurityException("new-key signature verification failed");
            }

            String computedNewPeerId = HashUtil.sha256Hex(newPubDer);
            if (!computedNewPeerId.equals(newPeerId)) {
                throw new SecurityException("new peer ID does not match supplied public key");
            }

            Map<String, Object> updated = new LinkedHashMap<>();
            updated.put("peer_name", newPeerName);
            updated.put("rsa_public_key_der_b64", newPubB64);
            updated.put("migrated_from", oldPeerId);

            contacts.remove(oldPeerId);
            contacts.put(newPeerId, updated);
            contactsStore.save(contacts);

            System.out.println("[INFO] Key migration accepted: " + newPeerName + " updated contact record");
            return true;
        } catch (Exception e) {
            System.out.println("[SECURITY ERROR] Key migration FAILED verification: " + e.getMessage());
            return false;
        }
    }
}