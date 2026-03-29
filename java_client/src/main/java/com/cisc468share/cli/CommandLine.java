package com.cisc468share.cli;

import com.cisc468share.discovery.MdnsService;
import com.cisc468share.files.ShareManager;

import java.util.Scanner;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;


public class CommandLine {
    private final ShareManager shareManager;
    private final MdnsService mdnsService;

    public CommandLine(ShareManager shareManager, MdnsService mdnsService) {
        this.shareManager = shareManager;
        this.mdnsService = mdnsService;
    }

    public void start() {

        Scanner scanner = new Scanner(System.in);
        System.out.println("Secure Share CLI started");
        while (true) {
            System.out.print("secure-share> ");
            String line = scanner.nextLine().trim();
            if (line.isEmpty()) continue;
            String[] parts = line.split("\\s+", 2);
            String cmd = parts[0];
            String arg = parts.length > 1 ? parts[1].trim() : "";
            switch (cmd){
                case "help" -> printHelp();
                case "peers" -> listPeers();
                case "share" -> shareFile(arg);
                case "get" -> getFile(arg);
                case "exit" -> { System.out.println("Exiting..."); return; }
                default -> System.out.println("Unknown command. Type 'help' for a list of commands.");
            }
        }
    }
    
    private void printHelp() {
        System.out.println("Available commands:");
        System.out.println("  help           show commands");
        System.out.println("  peers          list discovered peers");
        System.out.println("  share <file>   share a file into data/shared");
        System.out.println("  get <file>     fetch a file from a peer");
        System.out.println("  exit           quit program");
    }

    private void listPeers(){
        List<MdnsService.PeerInfo> peers = mdnsService.getDiscoveredPeers();
        if (peers.isEmpty()) {
            System.out.println("No peers discovered");
            return;
        } else {
            System.out.println("Discovered peers:");
            for (MdnsService.PeerInfo peer : peers) {
                System.out.println(" " + peer);
            }
        }
    }

    private void listSharedFiles() {
        List<String> files = shareManager.listFiles();
        if (files.isEmpty()) {
            System.out.println("No shared files available.");
            return;
        } else {
            System.out.println("Shared files:");
            for (String file : files) {
                System.out.println(" " + file);
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

    private void getFile(String filename) {
        if (filename.isEmpty()) {
            System.out.println("Usage: get <file>");
            return;
        }
        System.out.println("Fetching file from peer is not yet implemented.");
    }
    
}
