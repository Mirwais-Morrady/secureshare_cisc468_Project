package com.cisc468share.crypto;

public class SecureSession {

    public final String sessionId;
    public final byte[] sendKey;
    public final byte[] recvKey;

    public long sendSeq = 0;
    public long recvSeq = 0;

    public SecureSession(String id, byte[] sendKey, byte[] recvKey) {
        this.sessionId = id;
        this.sendKey = sendKey;
        this.recvKey = recvKey;
    }
}
