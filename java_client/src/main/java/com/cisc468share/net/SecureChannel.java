package com.cisc468share.net;

import com.cisc468share.crypto.AesGcmUtil;
import com.cisc468share.crypto.SecureSession;
import com.cisc468share.protocol.CanonicalJson;
import com.cisc468share.protocol.Serializer;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

public class SecureChannel {

    private final Socket socket;
    private final SecureSession session;

    public SecureChannel(Socket socket, SecureSession session) {
        this.socket = socket;
        this.session = session;
    }

    public void send(String msgType, Map<String, Object> msg) throws Exception {
        session.sendSeq += 1L;
        long seq = session.sendSeq;

        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);

        byte[] plaintext = Serializer.jsonDumpsBytes(msg);
        byte[] aad = buildAad(session.sessionId, seq, msgType);
        byte[] ciphertext = AesGcmUtil.encrypt(session.sendKey, nonce, plaintext, aad);

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("version", "1.0");
        envelope.put("session_id", session.sessionId);
        envelope.put("msg_seq", seq);
        envelope.put("msg_type", msgType);
        envelope.put("nonce_b64", Base64.getEncoder().encodeToString(nonce));
        envelope.put("aad_b64", Base64.getEncoder().encodeToString(aad));
        envelope.put("ciphertext_b64", Base64.getEncoder().encodeToString(ciphertext));

        byte[] frame = Framing.encodeFrame(Serializer.jsonDumpsBytes(envelope));
        OutputStream out = socket.getOutputStream();
        out.write(frame);
        out.flush();
    }

    public Map<String, Object> receive() throws Exception {
        InputStream in = socket.getInputStream();
        byte[] payload = Framing.decodeFrame(in);
        Map<String, Object> envelope = Serializer.jsonLoadsBytes(payload);

        String sessionId = (String) envelope.get("session_id");
        Number seqNumber = (Number) envelope.get("msg_seq");
        String msgType = (String) envelope.get("msg_type");
        String nonceB64 = (String) envelope.get("nonce_b64");
        String aadB64 = (String) envelope.get("aad_b64");
        String ciphertextB64 = (String) envelope.get("ciphertext_b64");

        if (!session.sessionId.equals(sessionId)) {
            throw new IllegalStateException("Session ID mismatch");
        }

        long seq = seqNumber.longValue();
        if (seq <= session.recvSeq) {
            throw new IllegalStateException("Replay or out-of-order message");
        }

        byte[] expectedAad = buildAad(sessionId, seq, msgType);
        byte[] aad = Base64.getDecoder().decode(aadB64);

        if (!java.util.Arrays.equals(expectedAad, aad)) {
            throw new IllegalStateException("AAD mismatch");
        }

        byte[] nonce = Base64.getDecoder().decode(nonceB64);
        byte[] ciphertext = Base64.getDecoder().decode(ciphertextB64);
        byte[] plaintext = AesGcmUtil.decrypt(session.recvKey, nonce, ciphertext, aad);

        session.recvSeq = seq;
        return Serializer.jsonLoadsBytes(plaintext);
    }

    private byte[] buildAad(String sessionId, long seq, String msgType) {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("msg_seq", seq);
        header.put("msg_type", msgType);
        header.put("session_id", sessionId);
        header.put("version", "1.0");
        return CanonicalJson.toBytes(header);
    }
}
