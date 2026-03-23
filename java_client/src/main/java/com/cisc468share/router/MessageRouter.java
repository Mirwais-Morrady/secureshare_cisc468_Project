package com.cisc468share.router;

import com.cisc468share.crypto.SecureSession;
import com.cisc468share.net.Framing;
import com.cisc468share.net.SecureChannel;
import com.cisc468share.protocol.MessageTypes;
import com.cisc468share.protocol.Serializer;

import java.net.Socket;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Routes decrypted protocol messages to the correct handler.
 *
 * After the handshake the SecureChannel handles encryption. The router
 * reads each message and calls the appropriate method.
 */
public class MessageRouter {

    private final Socket socket;
    private final SecureChannel channel;
    private final String peerName;
    private final String peerId;

    public MessageRouter(Socket socket, SecureSession session,
                         String peerName, String peerId) {
        this.socket = socket;
        this.channel = new SecureChannel(socket, session);
        this.peerName = peerName;
        this.peerId = peerId;
    }

    /** Main loop: receive, decrypt, dispatch. */
    public void run() {
        while (true) {
            try {
                Map<String, Object> msg = channel.receive();
                dispatch(msg);
            } catch (Exception e) {
                System.out.println("[NET] Connection closed: " + peerName);
                break;
            }
        }
    }

    private void dispatch(Map<String, Object> msg) {
        String type = (String) msg.get("type");
        if (type == null) return;

        switch (type) {
            case MessageTypes.LIST_FILES_REQUEST -> onListFiles();
            case MessageTypes.FILE_REQUEST       -> onFileRequest(msg);
            case MessageTypes.FILE_CHUNK         -> onFileChunk(msg);
            case MessageTypes.FILE_TRANSFER_COMPLETE -> onTransferComplete(msg);
            case MessageTypes.KEY_MIGRATION      -> onKeyMigration(msg);
            case MessageTypes.PING               -> sendMsg(Map.of("type", MessageTypes.PONG));
            default -> System.out.println("[NET] Unknown message type from " + peerName + ": " + type);
        }
    }

    private List<byte[]> chunks = new ArrayList<>();
    private Map<Integer, byte[]> chunkBuffer = new java.util.TreeMap<>();
    private String currentFile = null;

    private void onListFiles() {
        List<String> files = new ArrayList<>();
        // In a real application, retrieve from ShareManager
        sendMsg(Map.of("type", MessageTypes.LIST_FILES_RESPONSE, "files", files));
        System.out.println("[INFO] Sent file list to " + peerName);
    }

    private void onFileRequest(Map<String, Object> msg) {
        String filename = (String) msg.getOrDefault("file", "unknown");
        Number sizeNum = (Number) msg.getOrDefault("filesize", 0);
        long filesize = sizeNum.longValue();

        // Automatic consent for now (CLI integration would prompt the user)
        System.out.println("[INCOMING FILE REQUEST] From: " + peerName
                + "  File: " + filename + "  Size: " + filesize + " bytes");
        System.out.println("[INFO] Auto-accepting (CLI consent not yet integrated in Java)");

        currentFile = filename;
        chunkBuffer.clear();
        sendMsg(Map.of("type", MessageTypes.FILE_REQUEST_ACCEPT, "file", filename));
    }

    private void onFileChunk(Map<String, Object> msg) {
        String file = (String) msg.getOrDefault("file", "");
        Number idxNum = (Number) msg.getOrDefault("index", 0);
        int idx = idxNum.intValue();
        String hexData = (String) msg.getOrDefault("data", "");

        byte[] data = hexToBytes(hexData);
        chunkBuffer.put(idx, data);
    }

    private void onTransferComplete(Map<String, Object> msg) {
        String filename = (String) msg.getOrDefault("file", "");
        String expectedSha256 = (String) msg.get("sha256_hex");

        // Assemble
        int total = chunkBuffer.values().stream().mapToInt(b -> b.length).sum();
        byte[] assembled = new byte[total];
        int offset = 0;
        for (byte[] chunk : chunkBuffer.values()) {
            System.arraycopy(chunk, 0, assembled, offset, chunk.length);
            offset += chunk.length;
        }

        // Integrity check
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(assembled);
            String actualSha256 = bytesToHex(digest);

            if (expectedSha256 != null && !actualSha256.equals(expectedSha256)) {
                System.out.println("[SECURITY ERROR] Integrity check FAILED for '" + filename + "'!");
                System.out.println("  Expected: " + expectedSha256);
                System.out.println("  Actual:   " + actualSha256);
                System.out.println("  The file may have been tampered with in transit.");
                sendMsg(Map.of("type", MessageTypes.ERROR,
                        "message", "Integrity check failed for " + filename));
                return;
            }

            System.out.println("[INFO] '" + filename + "' received (" + assembled.length + " bytes)");
            System.out.println("[INFO] Integrity OK: SHA-256=" + actualSha256.substring(0, 16) + "...");

        } catch (Exception e) {
            System.out.println("[ERROR] Integrity check error: " + e.getMessage());
        }
    }

    private void onKeyMigration(Map<String, Object> msg) {
        String oldPeerId = (String) msg.getOrDefault("old_peer_id", "");
        System.out.println("[INFO] Key migration received from peer: " + oldPeerId.substring(0, Math.min(16, oldPeerId.length())) + "...");
        System.out.println("[INFO] Contact '" + msg.get("new_peer_name") + "' has migrated to a new key.");
        System.out.println("[INFO] Manual contact verification recommended before re-authentication.");
    }

    private void sendMsg(Map<String, Object> msg) {
        try {
            channel.send((String) msg.get("type"), msg);
        } catch (Exception e) {
            System.out.println("[ERROR] Failed to send message: " + e.getMessage());
        }
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
