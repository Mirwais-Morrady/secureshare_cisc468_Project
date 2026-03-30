package com.cisc468share.cli;

import com.cisc468share.crypto.HandshakeManager;
import com.cisc468share.crypto.IdentityManager;
import com.cisc468share.crypto.KeyMigrationUtil;
import com.cisc468share.crypto.ManifestManager;
import com.cisc468share.crypto.HashUtil;
import com.cisc468share.discovery.MdnsService;
import com.cisc468share.files.ShareManager;
import com.cisc468share.net.ConsentManager;
import com.cisc468share.net.FileTransfer;
import com.cisc468share.net.SecureChannel;
import com.cisc468share.net.TcpClient;
import com.cisc468share.protocol.CanonicalJson;
import com.cisc468share.protocol.MessageTypes;
import com.cisc468share.runtime.RuntimeLauncher;
import com.cisc468share.storage.ContactsStore;
import com.cisc468share.storage.ManifestStore;
import com.cisc468share.storage.VaultStore;

import java.net.Socket;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.TreeMap;


public class CommandLine {

    // ------------------------------------------------------------------
    // Inner types
    // ------------------------------------------------------------------

    private static class Conn {
        final Socket socket;
        final SecureChannel channel;
        final String peerId;
        final String peerName;
        final BlockingQueue<Map<String, Object>> inbox = new LinkedBlockingQueue<>();
        volatile boolean closed;
        volatile String closeReason;

        Conn(Socket socket, SecureChannel channel, String peerId, String peerName) {
            this.socket = socket;
            this.channel = channel;
            this.peerId = peerId;
            this.peerName = peerName;
            this.closed = false;
            this.closeReason = null;
        }
    }

    // ------------------------------------------------------------------
    // Fields
    // ------------------------------------------------------------------

    private final ShareManager    shareManager;
    private final MdnsService     mdnsService;
    private final Scanner         scanner;
    private final ConsentManager  consentManager;
    private final ManifestStore   manifestStore;
    private final ContactsStore   contactsStore;
    private final VaultStore      vaultStore;
    private final Path            identityDir;

    // Identity — mutable after rotate-key
    private String     peerName;
    private String     peerId;
    private byte[]     publicKeyDer;
    private PrivateKey privateKey;

    private final Map<String, Conn> connections = new HashMap<>();

    // ------------------------------------------------------------------
    // Constructor
    // ------------------------------------------------------------------

    public CommandLine(ShareManager shareManager, MdnsService mdnsService,
                       Scanner scanner, ConsentManager consentManager,
                       String peerName, String peerId, byte[] publicKeyDer,
                       PrivateKey privateKey, Path identityDir,
                       ManifestStore manifestStore, ContactsStore contactsStore,
                       VaultStore vaultStore) {
        this.shareManager  = shareManager;
        this.mdnsService   = mdnsService;
        this.scanner       = scanner;
        this.consentManager = consentManager;
        this.peerName      = peerName;
        this.peerId        = peerId;
        this.publicKeyDer  = publicKeyDer;
        this.privateKey    = privateKey;
        this.identityDir   = identityDir;
        this.manifestStore = manifestStore;
        this.contactsStore = contactsStore;
        this.vaultStore = vaultStore;
    }

    // ------------------------------------------------------------------
    // Main loop
    // ------------------------------------------------------------------

    public void start() {
        System.out.println("SecureShare CLI started. Type 'help' for commands.");
        while (true) {
            if (consentManager.hasPending()) {
                handleConsent();
                continue;
            }

            System.out.print("secure-share> ");
            System.out.flush();

            String line = null;
            while (line == null) {
                try {
                    if (System.in.available() > 0) {
                        line = scanner.nextLine().trim();
                    } else if (consentManager.hasPending()) {
                        System.out.println();
                        handleConsent();
                        System.out.print("secure-share> ");
                        System.out.flush();
                    } else {
                        Thread.sleep(100);
                    }
                } catch (InterruptedException ignored) {
                } catch (Exception e) {
                    return;
                }
            }

            if (line.isEmpty()) continue;

            String[] parts = line.split("\\s+", 3);
            String cmd = parts[0];
            String arg1 = parts.length > 1 ? parts[1].trim() : "";
            String arg2 = parts.length > 2 ? parts[2].trim() : "";

            switch (cmd) {
                case "help"       -> printHelp();
                case "peers"      -> listPeers();
                case "list"       -> listSharedFiles(arg1);
                case "share"      -> shareFile(arg1);
                case "store"      -> cmdStore(arg1);
                case "connect"    -> connectPeer(arg1);
                case "list-files" -> cmdListFiles(arg1);
                case "send"       -> cmdSend(arg1, arg2);
                case "request"    -> cmdRequest(arg1, arg2);
                case "fetch"      -> cmdFetch(arg1, arg2);
                case "vault"      -> cmdVault(arg1, arg2);
                case "rotate-key" -> cmdRotateKey();
                case "exit", "quit" -> { System.out.println("Exiting..."); return; }
                default -> System.out.println("Unknown command. Type 'help'");
            }
        }
    }

    // ------------------------------------------------------------------
    // Consent handler (main-thread only)
    // ------------------------------------------------------------------

    private void handleConsent() {
        try {
            ConsentManager.ConsentRequest req = consentManager.popPending();
            System.out.println();
            System.out.println("[CONSENT REQUIRED]");
            System.out.println("  Peer : " + req.peerName);
            System.out.println("  File : " + req.filename);
            System.out.println("  Size : " + req.filesize + " bytes");
            System.out.print("  Accept? [y/N]: ");
            System.out.flush();

            String response = scanner.hasNextLine() ? scanner.nextLine().trim().toLowerCase() : "n";
            boolean accepted = response.equals("y") || response.equals("yes");
            consentManager.respond(accepted);

            if (accepted) {
                System.out.println("[INFO] Accepted — receiving '" + req.filename + "' from " + req.peerName);
            } else {
                System.out.println("[INFO] Denied — rejected '" + req.filename + "' from " + req.peerName);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    // ------------------------------------------------------------------
    // Help / peers / list / share
    // ------------------------------------------------------------------

    private void printHelp() {
        System.out.println("Available commands:");
        System.out.println("  help                         show commands");
        System.out.println("  peers                        list discovered peers");
        System.out.println("  list                         list your own shared files");
        System.out.println("  list downloads               list files in data/downloads/");
        System.out.println("  share <file>                 copy file into data/shared and sign manifest");
        System.out.println("  store <file>                 store a local file in the encrypted vault");
        System.out.println("  connect <peer>               connect and authenticate with a peer");
        System.out.println("  list-files <peer>            list files shared by a peer (no consent needed)");
        System.out.println("  send <peer> <file>           send a file to a peer (they must consent)");
        System.out.println("  request <peer> <file>        request a file from a peer (they must consent)");
        System.out.println("  fetch <peer> <file>          fetch from redistributor and verify against manifest");
        System.out.println("  vault list                   list files stored in the encrypted vault");
        System.out.println("  vault get <file>             export a vault file to data/downloads/");
        System.out.println("  vault delete <file>          delete a file from the encrypted vault");
        System.out.println("  rotate-key                   generate new RSA key pair and notify connected peers");
        System.out.println("  exit                         quit program");
    }

    private void listPeers() {
        List<MdnsService.PeerInfo> peers = mdnsService.getDiscoveredPeers();
        if (peers.isEmpty()) {
            System.out.println("No peers discovered");
        } else {
            for (MdnsService.PeerInfo peer : peers) {
                String fullName = peer.name + "._cisc468share._tcp.local.";
                String selfTag  = peer.name.equals(peerName) ? " (self)" : "";
                System.out.println(fullName + " - " + peer.address + selfTag);
            }
        }
    }

    private void listSharedFiles(String arg) {
        if ("downloads".equals(arg)) {
            Path dlDir = Paths.get("data", "downloads");
            try {
                if (!Files.exists(dlDir)) { System.out.println("No downloads folder yet."); return; }
                List<Path> entries = Files.list(dlDir).filter(Files::isRegularFile).toList();
                if (entries.isEmpty()) {
                    System.out.println("Downloads folder is empty.");
                } else {
                    System.out.println("Files in data/downloads/:");
                    for (Path p : entries) System.out.println("  " + p.getFileName());
                }
            } catch (Exception e) {
                System.out.println("[ERROR] Could not list downloads: " + e.getMessage());
            }
            return;
        }
        List<String> files = shareManager.listFiles();
        if (files.isEmpty()) {
            System.out.println("No shared files.");
        } else {
            System.out.println("Shared files:");
            for (String f : files) System.out.println("  " + f);
        }
    }

    private void shareFile(String sourcePath) {
        if (sourcePath.isEmpty()) { System.out.println("Usage: share <file_path>"); return; }
        try {
            Path source = Path.of(sourcePath);
            if (!Files.exists(source) || !Files.isRegularFile(source)) {
                Path fallback = Paths.get("data", "downloads", sourcePath);
                if (Files.exists(fallback) && Files.isRegularFile(fallback)) {
                    source = fallback;
                } else {
                    System.out.println("[ERROR] File not found: " + sourcePath);
                    System.out.println("       Looked in: ./" + sourcePath + " and data/downloads/" + sourcePath);
                    return;
                }
            }
            shareManager.addFile(source);
            System.out.println("[OK] File shared: " + source.getFileName());
            System.out.println("     Stored encrypted at rest in the shared vault");

            // Build and sign a manifest for offline redistribution verification
            Map<String, Object> manifest = ManifestManager.buildManifest(peerId, peerName, source);
            Map<String, Object> signed   = ManifestManager.signManifest(privateKey, manifest);
            manifestStore.save(signed);
            System.out.println("[OK] Manifest signed and stored for '" + source.getFileName() + "'");
            System.out.println("     SHA-256 : " + signed.get("file_sha256_hex"));
            System.out.println("     Owner   : " + peerName + " (" + peerId.substring(0, 16) + "...)");

        } catch (Exception e) {
            System.out.println("[ERROR] share failed: " + e.getMessage());
        }
    }

    private void cmdStore(String sourcePath) {
        if (sourcePath.isEmpty()) {
            System.out.println("Usage: store <file_path>");
            return;
        }

        try {
            Path source = Path.of(sourcePath);
            if (!Files.exists(source) || !Files.isRegularFile(source)) {
                Path fallback = Paths.get("data", "downloads", sourcePath);
                if (Files.exists(fallback) && Files.isRegularFile(fallback)) {
                    source = fallback;
                } else {
                    System.out.println("[ERROR] File not found: " + sourcePath);
                    System.out.println("       Looked in: ./" + sourcePath + " and data/downloads/" + sourcePath);
                    return;
                }
            }

            vaultStore.storeFile(source.getFileName().toString(), Files.readAllBytes(source));
            System.out.println("[OK] Stored '" + source.getFileName() + "' in the encrypted vault.");
            System.out.println("     The plaintext file remains at its original location unless you remove it.");
        } catch (Exception e) {
            System.out.println("[ERROR] store failed: " + e.getMessage());
        }
    }

    private void cmdVault(String action, String remainder) {
        if (action.isEmpty()) {
            System.out.println("Usage:");
            System.out.println("  vault list");
            System.out.println("  vault get <file>");
            System.out.println("  vault delete <file>");
            return;
        }

        try {
            switch (action) {
                case "list" -> {
                    List<String> files = vaultStore.listFiles();
                    if (files.isEmpty()) {
                        System.out.println("Vault is empty.");
                    } else {
                        System.out.println("Encrypted vault files:");
                        for (String file : files) {
                            System.out.println("  " + file);
                        }
                    }
                }
                case "get" -> {
                    if (remainder.isEmpty()) {
                        System.out.println("Usage: vault get <file>");
                        return;
                    }
                    byte[] data = vaultStore.getFile(remainder);
                    Path downloads = Paths.get("data", "downloads");
                    Files.createDirectories(downloads);
                    Path outPath = downloads.resolve(remainder);
                    Files.write(outPath, data);
                    System.out.println("[OK] Exported '" + remainder + "' from vault to " + outPath);
                }
                case "delete" -> {
                    if (remainder.isEmpty()) {
                        System.out.println("Usage: vault delete <file>");
                        return;
                    }
                    vaultStore.deleteFile(remainder);
                    System.out.println("[OK] Deleted '" + remainder + "' from the encrypted vault.");
                }
                default -> {
                    System.out.println("Usage:");
                    System.out.println("  vault list");
                    System.out.println("  vault get <file>");
                    System.out.println("  vault delete <file>");
                }
            }
        } catch (Exception e) {
            System.out.println("[ERROR] vault command failed: " + e.getMessage());
        }
    }

    // ------------------------------------------------------------------
    // connect <peer>
    // ------------------------------------------------------------------

    private void connectPeer(String targetName) {
        if (targetName.isEmpty()) { System.out.println("Usage: connect <peer-name>"); return; }

        MdnsService.PeerInfo peer = findPeer(targetName);
        if (peer == null) {
            List<MdnsService.PeerInfo> all = mdnsService.getDiscoveredPeers();
            if (all.isEmpty()) {
                System.out.println("[ERROR] No peers discovered yet. Try 'peers' first.");
            } else {
                System.out.print("[ERROR] Peer '" + targetName + "' not found. Known: ");
                all.forEach(p -> System.out.print(shortName(p.name) + " "));
                System.out.println();
            }
            return;
        }

        System.out.println("[CONNECT] Connecting to " + targetName + " at " + peer.address + ":" + peer.port + " ...");

        try {
            Socket sock = TcpClient.connect(peer.address, peer.port);
            System.out.println("[CONNECT] TCP connection established.");
            System.out.println("[CONNECT] Starting mutual authentication handshake ...");

            HandshakeManager hm = new HandshakeManager(peerName, peerId, publicKeyDer, privateKey);
            HandshakeManager.HandshakeResult result = hm.executeClientHandshakeEx(sock);

            System.out.println();
            System.out.println("[AUTH] Handshake complete.");
            System.out.println("  Peer name       : " + result.remotePeerName);
            System.out.println("  Peer fingerprint: " + result.remotePeerId);
            System.out.println("  Session ID      : " + result.session.sessionId);
            System.out.println();
            System.out.println("[AUTH] Mutual authentication successful.");
            System.out.println("  - We verified " + result.remotePeerName + "'s RSA-PSS signature.");
            System.out.println("  - " + result.remotePeerName + " verified our RSA-PSS signature.");
            System.out.println("  - Session keys derived via ephemeral Diffie-Hellman.");
            System.out.println("  - All further communication is AES-256-GCM encrypted.");

            // Save peer's public key to contacts
            Map<String, Object> contactInfo = new LinkedHashMap<>();
            contactInfo.put("peer_name", result.remotePeerName);
            contactInfo.put("rsa_public_key_der_b64",
                    Base64.getEncoder().encodeToString(result.remotePublicKeyDer));
            contactsStore.add(result.remotePeerId, contactInfo);

            SecureChannel channel = new SecureChannel(sock, result.session);
                Conn conn = new Conn(sock, channel, result.remotePeerId, result.remotePeerName);
                connections.put(targetName, conn);
                startConnectionReader(targetName, conn);

            System.out.println();
            System.out.println("[OK] Connected to '" + targetName + "'. You can now run:");
            System.out.println("  list-files " + targetName + "     — see their shared files");
            System.out.println("  send " + targetName + " <file>    — send a file (they will be prompted)");
            System.out.println("  request " + targetName + " <file> — request a file from them");

        } catch (Exception e) {
            System.out.println("[ERROR] Connect failed: " + e.getMessage());
        }
    }

    // ------------------------------------------------------------------
    // list-files <peer>
    // ------------------------------------------------------------------

    private void cmdListFiles(String targetName) {
        if (targetName.isEmpty()) { System.out.println("Usage: list-files <peer-name>"); return; }
        Conn conn = getOrConnect(targetName);
        if (conn == null) return;

        try {
            conn.channel.send(MessageTypes.LIST_FILES_REQUEST,
                    Map.of("type", MessageTypes.LIST_FILES_REQUEST));

            Map<String, Object> resp = waitForMessage(conn);
            if (!MessageTypes.LIST_FILES_RESPONSE.equals(resp.get("type"))) {
                System.out.println("[ERROR] Unexpected response: " + resp.get("type")); return;
            }
            @SuppressWarnings("unchecked")
            List<String> files = (List<String>) resp.getOrDefault("files", List.of());
            if (files.isEmpty()) {
                System.out.println("[LIST-FILES] " + targetName + " has no shared files.");
            } else {
                System.out.println("[LIST-FILES] Files shared by '" + targetName + "':");
                for (String f : files) System.out.println("  " + f);
            }
        } catch (Exception e) {
            System.out.println("[ERROR] list-files failed: " + e.getMessage());
            connections.remove(targetName);
        }
    }

    // ------------------------------------------------------------------
    // send <peer> <file>
    // ------------------------------------------------------------------

    private void cmdSend(String targetName, String filename) {
        if (targetName.isEmpty() || filename.isEmpty()) {
            System.out.println("Usage: send <peer-name> <filename>"); return;
        }

        // Resolve file: try as-is, then data/shared/
        Path filePath = Paths.get(filename);
        byte[] sharedData = null;
        if (!Files.exists(filePath)) {
            if (shareManager.hasFile(filename)) {
                sharedData = shareManager.getFileBytes(filename);
            } else {
                System.out.println("[ERROR] File not found: " + filename); return;
            }
        }

        Conn conn = getOrConnect(targetName);
        if (conn == null) return;

        try {
            long filesize = sharedData != null ? sharedData.length : Files.size(filePath);
            System.out.println("[SEND] File     : " + filename);
            System.out.println("[SEND] To       : " + targetName);
            System.out.println("[SEND] Sending FILE_REQUEST — waiting for consent ...");
            System.out.println("       >>> Watch the other terminal for the consent prompt <<<");

            conn.channel.send(MessageTypes.FILE_REQUEST, Map.of(
                    "type", MessageTypes.FILE_REQUEST,
                    "file", filename,
                    "filesize", filesize));

                Map<String, Object> resp = waitForMessage(conn);
            String respType = (String) resp.get("type");

            if (MessageTypes.FILE_REQUEST_DENY.equals(respType)) {
                System.out.println("[INFO] '" + targetName + "' denied: " + resp.getOrDefault("reason", "no reason"));
                return;
            }
            if (MessageTypes.ERROR.equals(respType)) {
                System.out.println("[ERROR] " + targetName + ": " + resp.get("message")); return;
            }
            if (!MessageTypes.FILE_REQUEST_ACCEPT.equals(respType)) {
                System.out.println("[ERROR] Unexpected response: " + respType); return;
            }

            System.out.println("[INFO] '" + targetName + "' accepted — sending file ...");

            byte[] data   = sharedData != null ? sharedData : Files.readAllBytes(filePath);
            List<byte[]> chunks = com.cisc468share.files.Chunker.chunkBytes(data);
            for (int i = 0; i < chunks.size(); i++) {
                conn.channel.send(MessageTypes.FILE_CHUNK, Map.of(
                        "type",  MessageTypes.FILE_CHUNK,
                        "file",  filename,
                        "index", i,
                        "data",  HashUtil.toHex(chunks.get(i))));
            }
            String sha256 = computeSha256Hex(data);
            conn.channel.send(MessageTypes.FILE_TRANSFER_COMPLETE, Map.of(
                    "type",       MessageTypes.FILE_TRANSFER_COMPLETE,
                    "file",       filename,
                    "sha256_hex", sha256));

            System.out.println("[OK] '" + filename + "' sent to '" + targetName + "'.");
            System.out.println("  Size      : " + data.length + " bytes");
            System.out.println("  SHA-256   : " + sha256);
            System.out.println("  Transport : AES-256-GCM encrypted end-to-end");

        } catch (Exception e) {
            System.out.println("[ERROR] send failed: " + e.getMessage());
            connections.remove(targetName);
        }
    }

    // ------------------------------------------------------------------
    // request <peer> <file>
    // ------------------------------------------------------------------

    private void cmdRequest(String targetName, String filename) {
        if (targetName.isEmpty() || filename.isEmpty()) {
            System.out.println("Usage: request <peer-name> <filename>"); return;
        }

        Conn conn = getOrConnect(targetName);
        if (conn == null) return;

        System.out.println("[REQUEST] File     : " + filename);
        System.out.println("[REQUEST] From     : " + targetName);
        System.out.println("[REQUEST] Sending GET_FILE_REQUEST — waiting for consent ...");
        System.out.println("          >>> Watch the other terminal for the consent prompt <<<");

        try {
            conn.channel.send(MessageTypes.GET_FILE_REQUEST,
                    Map.of("type", MessageTypes.GET_FILE_REQUEST, "file", filename));

            Map<String, Object> resp = waitForMessage(conn);
            String respType = (String) resp.get("type");

            if (MessageTypes.FILE_REQUEST_DENY.equals(respType)) {
                System.out.println("[INFO] '" + targetName + "' denied: " + resp.getOrDefault("reason", "no reason"));
                return;
            }
            if (MessageTypes.ERROR.equals(respType)) {
                System.out.println("[ERROR] " + targetName + ": " + resp.get("message")); return;
            }
            if (!MessageTypes.FILE_REQUEST_ACCEPT.equals(respType)) {
                System.out.println("[ERROR] Unexpected response: " + respType); return;
            }

            System.out.println("[INFO] '" + targetName + "' accepted — receiving file ...");

            receiveFileChunks(conn, filename, null, null, null);

        } catch (Exception e) {
            System.out.println("[ERROR] request failed: " + e.getMessage());
            connections.remove(targetName);
        }
    }

    // ------------------------------------------------------------------
    // fetch <peer> <file>
    // ------------------------------------------------------------------

    private void cmdFetch(String targetName, String filename) {
        if (targetName.isEmpty() || filename.isEmpty()) {
            System.out.println("Usage: fetch <peer-name> <filename>");
            System.out.println("  e.g. fetch python-peer project_report.txt");
            return;
        }

        // Look up manifest
        Map<String, Object> manifest = manifestStore.get(filename);
        if (manifest == null) {
            System.out.println("[ERROR] No signed manifest found for '" + filename + "'.");
            System.out.println("  Run 'share <file>' on the original owner's client first,");
            System.out.println("  or use 'request' to get the file without manifest verification.");
            return;
        }

        String ownerPeerId   = (String) manifest.get("owner_peer_id");
        String ownerPeerName = (String) manifest.get("owner_peer_name");
        String expectedSha   = (String) manifest.get("file_sha256_hex");

        System.out.println("[FETCH] File            : " + filename);
        System.out.println("[FETCH] Fetching from   : " + targetName + "  (redistributor)");
        System.out.println("[FETCH] Original owner  : " + ownerPeerName + " (" + ownerPeerId.substring(0, 16) + "...)");
        System.out.println("[FETCH] Expected SHA-256: " + expectedSha.substring(0, 32) + "...");
        System.out.println("[FETCH] Owner may be offline — verifying via signed manifest");
        System.out.println();

        // Resolve owner's public key
        PublicKey ownerPubKey = null;
        Map<String, Object> ownerContact = contactsStore.get(ownerPeerId);
        if (ownerContact != null) {
            try {
                byte[] der = Base64.getDecoder().decode((String) ownerContact.get("rsa_public_key_der_b64"));
                ownerPubKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
                System.out.println("[INFO] Owner's public key found in contacts.");
            } catch (Exception e) {
                System.out.println("[WARN] Could not load owner's public key: " + e.getMessage());
            }
        } else if (peerId.equals(ownerPeerId)) {
            try {
                ownerPubKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyDer));
                System.out.println("[INFO] We are the original owner — using our own public key.");
            } catch (Exception e) { /* ignore */ }
        } else {
            System.out.println("[WARN] Owner's public key not in contacts — manifest signature cannot be verified.");
        }

        Conn conn = getOrConnect(targetName);
        if (conn == null) return;

        System.out.println("[FETCH] Requesting '" + filename + "' from '" + targetName + "' ...");
        System.out.println("        >>> Watch the other terminal for the consent prompt <<<");

        try {
            conn.channel.send(MessageTypes.GET_FILE_REQUEST,
                    Map.of("type", MessageTypes.GET_FILE_REQUEST, "file", filename));

            Map<String, Object> resp = waitForMessage(conn);
            String respType = (String) resp.get("type");

            if (MessageTypes.FILE_REQUEST_DENY.equals(respType)) {
                System.out.println("[INFO] '" + targetName + "' denied: " + resp.getOrDefault("reason", "no reason"));
                return;
            }
            if (MessageTypes.ERROR.equals(respType)) {
                System.out.println("[ERROR] " + targetName + ": " + resp.get("message")); return;
            }
            if (!MessageTypes.FILE_REQUEST_ACCEPT.equals(respType)) {
                System.out.println("[ERROR] Unexpected response: " + respType); return;
            }

            System.out.println("[INFO] '" + targetName + "' accepted — receiving file ...");

            receiveFileChunks(conn, filename, expectedSha, manifest, ownerPubKey);

        } catch (Exception e) {
            System.out.println("[ERROR] fetch failed: " + e.getMessage());
            connections.remove(targetName);
        }
    }

    // ------------------------------------------------------------------
    // rotate-key
    // ------------------------------------------------------------------

    private void cmdRotateKey() {
        System.out.println("[ROTATE-KEY] Generating new RSA-2048 key pair ...");
        try {
            KeyPair newKp = IdentityManager.generateRSA();
            PrivateKey newPriv = newKp.getPrivate();
            PublicKey  newPub  = newKp.getPublic();
            byte[]     newPubDer  = newPub.getEncoded();
            String     newPeerId  = HashUtil.sha256Hex(newPubDer);
            System.out.println("[ROTATE-KEY] New peer ID : " + newPeerId.substring(0, 32) + "...");

            // Build KEY_MIGRATION message
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("type",                     MessageTypes.KEY_MIGRATION);
            body.put("proto_ver",                "1.0");
            body.put("old_peer_id",              peerId);
            body.put("new_peer_id",              newPeerId);
            body.put("new_peer_name",            peerName);
            body.put("new_rsa_public_key_der_b64", Base64.getEncoder().encodeToString(newPubDer));

            byte[] oldSig = IdentityManager.sign(privateKey, CanonicalJson.toBytes(body));
            body.put("old_key_signature_b64", Base64.getEncoder().encodeToString(oldSig));

            Map<String, Object> bodyForNewSig = new LinkedHashMap<>(body);
            bodyForNewSig.remove("old_key_signature_b64");
            byte[] newSig = IdentityManager.sign(newPriv, CanonicalJson.toBytes(bodyForNewSig));
            body.put("new_key_signature_b64", Base64.getEncoder().encodeToString(newSig));

            System.out.println("[ROTATE-KEY] Migration message built and signed with both keys.");

            // Broadcast to all active connections
            if (connections.isEmpty()) {
                System.out.println("[ROTATE-KEY] No active connections — migration message not broadcast.");
            } else {
                for (Map.Entry<String, Conn> entry : connections.entrySet()) {
                    try {
                        entry.getValue().channel.send(MessageTypes.KEY_MIGRATION, body);
                        System.out.println("[ROTATE-KEY] Sent KEY_MIGRATION to '" + entry.getKey() + "'");
                    } catch (Exception e) {
                        System.out.println("[WARN] Could not notify '" + entry.getKey() + "': " + e.getMessage());
                    }
                }
            }

            // Promote new keys to disk
            Path identityDirOld = identityDir.resolve("old");
            Files.createDirectories(identityDirOld);
            for (String fname : new String[]{"private_key.pem", "public_key.pem"}) {
                Path src = identityDir.resolve(fname);
                if (Files.exists(src)) Files.copy(src, identityDirOld.resolve(fname), StandardCopyOption.REPLACE_EXISTING);
            }
            RuntimeLauncher.savePrivateKeyPem(newPriv, identityDir.resolve("private_key.pem"));
            RuntimeLauncher.savePublicKeyPem(newPub,   identityDir.resolve("public_key.pem"));

            // Update in-process identity
            String oldId = peerId;
            this.privateKey   = newPriv;
            this.publicKeyDer = newPubDer;
            this.peerId       = newPeerId;

            // Close all connections — they used the old identity
            for (Conn c : connections.values()) {
                try { c.socket.close(); } catch (Exception ignored) {}
            }
            connections.clear();

            System.out.println();
            System.out.println("[OK] Key rotation complete.");
            System.out.println("  Old peer ID : " + oldId.substring(0, 32) + "...");
            System.out.println("  New peer ID : " + newPeerId.substring(0, 32) + "...");
            System.out.println("  Old keys backed up to: data/identity/old/");
            System.out.println("  New keys now active.");
            System.out.println();
            System.out.println("[INFO] All existing connections closed.");
            System.out.println("       Reconnect to peers — they now know your new public key.");

        } catch (Exception e) {
            System.out.println("[ERROR] rotate-key failed: " + e.getMessage());
        }
    }

    // ------------------------------------------------------------------
    // Shared file-receive helper (used by request and fetch)
    // ------------------------------------------------------------------

    /**
     * Reads FILE_CHUNK + FILE_TRANSFER_COMPLETE from the channel.
     * If expectedSha != null, verifies SHA-256 against it.
     * If manifest != null and ownerPubKey != null, verifies manifest signature.
    * Saves the file to the encrypted vault.
     */
    private void receiveFileChunks(Conn conn, String filename,
                                   String expectedSha,
                                   Map<String, Object> manifest,
                                   PublicKey ownerPubKey) throws Exception {
        TreeMap<Integer, byte[]> chunkBuffer = new TreeMap<>();

        while (true) {
            Map<String, Object> msg = waitForMessage(conn);
            String t = (String) msg.get("type");

            if (MessageTypes.FILE_CHUNK.equals(t)) {
                int idx = ((Number) msg.getOrDefault("index", 0)).intValue();
                byte[] data = hexToBytes((String) msg.getOrDefault("data", ""));
                chunkBuffer.put(idx, data);

            } else if (MessageTypes.FILE_TRANSFER_COMPLETE.equals(t)) {
                // If SHA was in the completion message and we didn't get it from manifest
                if (expectedSha == null) {
                    expectedSha = (String) msg.get("sha256_hex");
                }

                // Assemble
                int total = chunkBuffer.values().stream().mapToInt(b -> b.length).sum();
                byte[] assembled = new byte[total];
                int off = 0;
                for (byte[] chunk : chunkBuffer.values()) {
                    System.arraycopy(chunk, 0, assembled, off, chunk.length);
                    off += chunk.length;
                }

                System.out.println();
                System.out.println("[VERIFY] Received " + String.format("%,d", assembled.length) + " bytes.");
                System.out.println();

                // SHA-256 check
                String actualSha = computeSha256Hex(assembled);
                if (expectedSha != null) {
                    if (actualSha.equals(expectedSha)) {
                        System.out.println("[VERIFY] SHA-256 check : PASSED");
                        System.out.println("         Expected : " + expectedSha);
                        System.out.println("         Actual   : " + actualSha);
                    } else {
                        System.out.println("[SECURITY ERROR] SHA-256 check FAILED!");
                        System.out.println("  Expected : " + expectedSha);
                        System.out.println("  Actual   : " + actualSha);
                        System.out.println("  The file may have been tampered with. Discarding.");
                        return;
                    }
                }

                // Manifest signature check
                if (manifest != null && ownerPubKey != null) {
                    try {
                        boolean ok = ManifestManager.verifyManifest(ownerPubKey, manifest);
                        if (ok) {
                            String ownerName = (String) manifest.getOrDefault("owner_peer_name", "owner");
                            System.out.println("[VERIFY] Manifest signature : PASSED");
                            System.out.println("         The manifest was signed by " + ownerName + ".");
                            System.out.println("         Even though " + ownerName + " may be offline,");
                            System.out.println("         the file is provably the same one they offered.");
                        } else {
                            System.out.println("[SECURITY ERROR] Manifest signature FAILED. Discarding.");
                            return;
                        }
                    } catch (Exception e) {
                        System.out.println("[SECURITY ERROR] Manifest signature error: " + e.getMessage());
                        System.out.println("  The manifest may be forged. Discarding.");
                        return;
                    }
                }

                // Save to encrypted vault
                vaultStore.storeFile(filename, assembled);

                System.out.println();
                System.out.println("[OK] '" + filename + "' received, verified, and saved.");
                System.out.println("  Saved to  : encrypted vault");
                System.out.println("  Transport : AES-256-GCM encrypted end-to-end");
                return;

            } else if (MessageTypes.ERROR.equals(t)) {
                System.out.println("[ERROR] Peer reported error: " + msg.get("message"));
                return;
            } else {
                System.out.println("[ERROR] Unexpected message during transfer: " + t);
                return;
            }
        }
    }

    // ------------------------------------------------------------------
    // Utilities
    // ------------------------------------------------------------------

    private Conn getOrConnect(String name) {
        Conn conn = connections.get(name);
        if (conn != null) return conn;
        System.out.println("[INFO] Not connected to '" + name + "'. Connecting first...");
        connectPeer(name);
        return connections.get(name);
    }

    private MdnsService.PeerInfo findPeer(String name) {
        for (MdnsService.PeerInfo p : mdnsService.getDiscoveredPeers()) {
            if (shortName(p.name).equals(name) || p.name.equals(name)) return p;
        }
        return null;
    }

    private static String shortName(String fullName) {
        int dot = fullName.indexOf('.');
        return dot >= 0 ? fullName.substring(0, dot) : fullName;
    }

    private void startConnectionReader(String targetName, Conn conn) {
        Thread reader = new Thread(() -> {
            while (!conn.closed) {
                try {
                    Map<String, Object> msg = conn.channel.receive();
                    String type = (String) msg.get("type");

                    if (MessageTypes.KEY_MIGRATION.equals(type)) {
                        String oldPeerId = (String) msg.getOrDefault("old_peer_id", "");
                        System.out.println("[INFO] Key migration received from peer: "
                                + oldPeerId.substring(0, Math.min(16, oldPeerId.length())) + "...");
                        if (!KeyMigrationUtil.applyMigrationMessage(msg, contactsStore)) {
                            System.out.println("[INFO] Manual contact verification recommended before re-authentication.");
                        }
                        continue;
                    }

                    conn.inbox.put(msg);
                } catch (Exception e) {
                    conn.closed = true;
                    conn.closeReason = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();

                    LinkedHashMap<String, Object> closedMsg = new LinkedHashMap<>();
                    closedMsg.put("type", MessageTypes.ERROR);
                    closedMsg.put("message", "Connection closed: " + conn.closeReason);
                    conn.inbox.offer(closedMsg);

                    Conn current = connections.get(targetName);
                    if (current == conn) {
                        connections.remove(targetName);
                    }
                    System.out.println("[NET] Connection closed: " + conn.peerName + " — " + conn.closeReason);
                    break;
                }
            }
        }, "secure-share-reader-" + targetName);
        reader.setDaemon(true);
        reader.start();
    }

    private Map<String, Object> waitForMessage(Conn conn) throws Exception {
        Map<String, Object> msg = conn.inbox.take();
        String type = (String) msg.get("type");
        if (MessageTypes.ERROR.equals(type) && conn.closed) {
            throw new IllegalStateException((String) msg.getOrDefault("message", "connection closed"));
        }
        return msg;
    }

    private static String computeSha256Hex(byte[] data) throws Exception {
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
        return HashUtil.toHex(md.digest(data));
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2)
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        return data;
    }
}
