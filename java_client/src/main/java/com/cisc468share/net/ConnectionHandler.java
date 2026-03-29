package com.cisc468share.net;

import com.cisc468share.crypto.HandshakeManager;
import com.cisc468share.files.ShareManager;
import com.cisc468share.crypto.SecureSession;
import com.cisc468share.router.MessageRouter;

import java.net.Socket;

/**
 * Handles an incoming TCP connection:
 * 1. Performs the server-side cryptographic handshake (authenticates the peer).
 * 2. Saves the peer's verified identity to contacts.
 * 3. Delegates all subsequent messages to the MessageRouter.
 */
public class ConnectionHandler {

    private final HandshakeManager handshakeManager;

    /** Construct with identity information for the handshake. */
    private final ShareManager shareManager;

    /** Construct with identity information for the handshake. */
    public ConnectionHandler(HandshakeManager handshakeManager, ShareManager shareManager) {
        this.handshakeManager = handshakeManager;
        this.shareManager = shareManager;
    }

    /** Construct without identity — plain echo mode for testing. */
    public ConnectionHandler() {
        this.handshakeManager = null;
        this.shareManager = null;
    }

    public void handle(Socket socket) {
        System.out.println("[NET] Connection from " + socket.getRemoteSocketAddress());

        if (handshakeManager == null) {
            // Plain mode (compatibility / testing)
            handlePlain(socket);
            return;
        }

        try {
            SecureSession session = handshakeManager.executeServerHandshake(socket);
            System.out.println("[NET] Handshake complete — session: " + session.sessionId);

            MessageRouter router = new MessageRouter(socket, session, "peer", "unknown", shareManager);
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
