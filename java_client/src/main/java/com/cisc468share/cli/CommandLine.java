package com.cisc468share.cli;

import com.cisc468share.discovery.MdnsService;
import com.cisc468share.files.ShareManager;
import com.cisc468share.net.ConsentManager;

import java.util.Scanner;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;


public class CommandLine {
    private final ShareManager shareManager;
    private final MdnsService mdnsService;
    private final Scanner scanner;
    private final ConsentManager consentManager;

    public CommandLine(ShareManager shareManager, MdnsService mdnsService,
                       Scanner scanner, ConsentManager consentManager) {
        this.shareManager    = shareManager;
        this.mdnsService     = mdnsService;
        this.scanner         = scanner;
        this.consentManager  = consentManager;
    }

    public void start() {
        System.out.println("Secure Share CLI started");
        while (true) {

            // Check for a pending consent request before printing the prompt.
            // The background TCP thread queued it; we handle it here on the
            // main thread so only one caller touches the Scanner at a time.
            if (consentManager.hasPending()) {
                handleConsent();
                continue;
            }

            System.out.print("secure-share> ");
            System.out.flush();

            // Poll with System.in.available() — non-blocking check so we can
            // detect consent requests that arrive while waiting for user input.
            // scanner.hasNextLine() blocks forever and would prevent consent
            // prompts from appearing until the user presses Enter.
            String line = null;
            while (line == null) {
                try {
                    if (System.in.available() > 0) {
                        line = scanner.nextLine().trim();
                    } else if (consentManager.hasPending()) {
                        System.out.println();   // newline after "secure-share> "
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
            String[] parts = line.split("\\s+", 2);
            String cmd = parts[0];
            String arg = parts.length > 1 ? parts[1].trim() : "";
            switch (cmd) {
                case "help"  -> printHelp();
                case "peers" -> listPeers();
                case "list"  -> listSharedFiles();
                case "share" -> shareFile(arg);
                case "exit"  -> { System.out.println("Exiting..."); return; }
                default      -> System.out.println("Unknown command. Type 'help' for a list of commands.");
            }
        }
    }

    private void handleConsent() {
        try {
            ConsentManager.ConsentRequest req = consentManager.popPending();
            System.out.println();
            System.out.println("[INCOMING FILE REQUEST]");
            System.out.println("  From : " + req.peerName);
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

    private void printHelp() {
        System.out.println("Available commands:");
        System.out.println("  help           show commands");
        System.out.println("  peers          list discovered peers");
        System.out.println("  list           list your shared files");
        System.out.println("  share <file>   share a file into data/shared");
        System.out.println("  exit           quit program");
    }

    private void listPeers() {
        List<MdnsService.PeerInfo> peers = mdnsService.getDiscoveredPeers();
        if (peers.isEmpty()) {
            System.out.println("No peers discovered");
        } else {
            System.out.println("Discovered peers:");
            for (MdnsService.PeerInfo peer : peers) {
                System.out.println("  " + peer);
            }
        }
    }

    private void listSharedFiles() {
        List<String> files = shareManager.listFiles();
        if (files.isEmpty()) {
            System.out.println("No shared files available.");
        } else {
            System.out.println("Shared files:");
            for (String file : files) {
                System.out.println("  " + file);
            }
        }
    }

    private void shareFile(String sourcePath) {
        if (sourcePath.isEmpty()) {
            System.out.println("Usage: share <file_path>");
            return;
        }
        try {
            Path source = Path.of(sourcePath);
            if (!Files.exists(source) || !Files.isRegularFile(source)) {
                System.out.println("File not found: " + sourcePath);
                return;
            }
            Path destination = shareManager.getSharedDir().resolve(source.getFileName());
            Files.createDirectories(shareManager.getSharedDir());
            Files.copy(source, destination, StandardCopyOption.REPLACE_EXISTING);
            System.out.println("File shared: " + destination.getFileName());
        } catch (Exception e) {
            System.out.println("Failed to share file: " + e.getMessage());
        }
    }
}
