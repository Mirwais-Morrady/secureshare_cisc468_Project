package com.cisc468share.net;

import com.cisc468share.crypto.HandshakeManager;
import com.cisc468share.crypto.HashUtil;
import com.cisc468share.crypto.SecureSession;
import com.cisc468share.files.ShareManager;
import com.cisc468share.net.ConsentManager;
import com.cisc468share.router.MessageRouter;
import com.cisc468share.storage.ContactsStore;

import java.net.Socket;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Handles an incoming TCP connection:
 * 1. Performs the server-side cryptographic handshake (authenticates the peer).
 * 2. Saves the peer's verified identity to contacts.
 * 3. Delegates all subsequent messages to the MessageRouter.
 */
public class ConnectionHandler {

    private final HandshakeManager handshakeManager;
    private final ShareManager shareManager;
    private final ConsentManager consentManager;
    private final ContactsStore contactsStore;

    public ConnectionHandler(HandshakeManager handshakeManager, ShareManager shareManager,
                             ConsentManager consentManager, ContactsStore contactsStore) {
        this.handshakeManager = handshakeManager;
        this.shareManager = shareManager;
        this.consentManager = consentManager;
        this.contactsStore = contactsStore;
    }

    /** Construct without identity — plain echo mode for testing. */
    public ConnectionHandler() {
        this.handshakeManager = null;
        this.shareManager = null;
        this.consentManager = null;
        this.contactsStore = null;
    }

    public void handle(Socket socket) {
        System.out.println("[NET] Connection from " + socket.getRemoteSocketAddress());

        if (handshakeManager == null) {
            handlePlain(socket);
            return;
        }

        try {
            HandshakeManager.HandshakeResult result =
                    handshakeManager.executeServerHandshakeEx(socket);
            SecureSession session = result.session;
            System.out.println("[AUTH] Handshake complete.");
            System.out.println("  Peer name       : " + result.remotePeerName);
            System.out.println("  Peer fingerprint: " + result.remotePeerId);
            System.out.println("  Session ID      : " + session.sessionId);
            System.out.println();
            System.out.println("[AUTH] Mutual authentication successful.");
            System.out.println("  - We verified " + result.remotePeerName + "'s RSA-PSS signature.");
            System.out.println("  - " + result.remotePeerName + " verified our RSA-PSS signature.");
            System.out.println("  - Session keys derived via ephemeral Diffie-Hellman (new keys, never stored).");
            System.out.println("  - All further communication is AES-256-GCM encrypted.");

            // Save the connecting peer's public key to contacts
            if (contactsStore != null && result.remotePublicKeyDer != null) {
                Map<String, Object> info = new LinkedHashMap<>();
                info.put("peer_name", result.remotePeerName);
                info.put("rsa_public_key_der_b64",
                        Base64.getEncoder().encodeToString(result.remotePublicKeyDer));
                contactsStore.add(result.remotePeerId, info);
            }

            MessageRouter router = new MessageRouter(socket, session,
                    result.remotePeerName, result.remotePeerId,
                    shareManager, consentManager, contactsStore);
            router.run();

        } catch (Exception e) {
            System.out.println("[ERROR] Connection failed: " + e.getMessage());
        } finally {
            try { socket.close(); } catch (Exception ignored) {}
        }
    }

    private void handlePlain(Socket socket) {
        try {
            java.io.InputStream in = socket.getInputStream();
            while (true) {
                byte[] payload = Framing.decodeFrame(in);
                System.out.println("[NET] Received " + payload.length + " bytes");
            }
        } catch (Exception e) {
            System.out.println("[NET] Connection closed");
        } finally {
            try { socket.close(); } catch (Exception ignored) {}
        }
    }
}
