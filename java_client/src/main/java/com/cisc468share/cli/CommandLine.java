package com.cisc468share.cli;

import java.util.Scanner;

public class CommandLine {

    public void start() {

        Scanner scanner = new Scanner(System.in);

        System.out.println("Secure Share CLI started");

        while (true) {

            System.out.print("secure-share> ");

            String cmd = scanner.nextLine();

            if ("exit".equals(cmd) || "quit".equals(cmd)) {

                break;

            }

            if ("help".equals(cmd)) {

                System.out.println("Commands: help peers list share get exit");

            } else {

                System.out.println("Unknown command");

            }

        }

    }
}
