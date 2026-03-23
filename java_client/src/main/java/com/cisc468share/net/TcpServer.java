package com.cisc468share.net;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class TcpServer {

    private final int port;
    private final ConnectionHandler handler;

    public TcpServer(int port, ConnectionHandler handler) {
        this.port = port;
        this.handler = handler;
    }

    public void start() throws IOException {

        ServerSocket server = new ServerSocket(port);

        System.out.println("TCP server listening on port " + port);

        while (true) {
            Socket socket = server.accept();
            new Thread(() -> handler.handle(socket)).start();
        }
    }
}
