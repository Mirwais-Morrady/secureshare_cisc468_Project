package com.cisc468share.net;

import java.net.Socket;

public class TcpClient {

    public static Socket connect(String host, int port) throws Exception {

        return new Socket(host, port);

    }
}
