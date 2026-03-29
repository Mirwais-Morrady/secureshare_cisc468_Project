package com.cisc468share.net;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class TcpServer {

    private final ServerSocket serverSocket;
    private final ConnectionHandler handler;

    /** Use a pre-bound ServerSocket — no race condition between port selection and binding. */
    public TcpServer(ServerSocket serverSocket, ConnectionHandler handler) {
        this.serverSocket = serverSocket;
        this.handler = handler;
    }

    public void start() throws IOException {
        System.out.println("TCP server listening on 0.0.0.0:" + serverSocket.getLocalPort());
        while (true) {
            Socket socket = serverSocket.accept();
            new Thread(() -> handler.handle(socket)).start();
        }
    }
}
