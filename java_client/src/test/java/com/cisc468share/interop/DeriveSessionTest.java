package com.cisc468share.interop;

import com.cisc468share.crypto.HkdfUtil;
import com.cisc468share.crypto.SecureSession;
import com.cisc468share.net.SessionManager;
import com.cisc468share.protocol.HandshakeUtil;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests that Java session key derivation using fixed vectors produces
 * consistent results. When Python computes keys from the same vectors,
 * they must match.
 */
public class DeriveSessionTest {

    // Fixed CLIENT_HELLO vector
    static final Map<String, Object> CLIENT_HELLO = buildClientHello();
    static final Map<String, Object> SERVER_HELLO = buildServerHello();

    private static Map<String, Object> buildClientHello() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("type", "CLIENT_HELLO");
        m.put("proto_ver", "1.0");
        m.put("peer_name", "python-peer");
        m.put("peer_id", "68bf78cc91c41ebfc206ea48b40b9a5034efec1ff3c3223ca659fec53bfda86a");
        m.put("rsa_public_key_der_b64", "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAraHchP+bl8IcNjjysrgZ40bsLOPoCLsPH9cRWgm8nE25OZJ9BCOsr1AMDJ+iH0kKO6D0oc9IEPBG1EHfnVMs0A1DAmGyKUeIocOfeW24xKUV5Seu1mtmxirb/qFgj+Mq/810C9+OJN8lmX1IWxYtPVmUs6TA6DgKDHoxBxjZmvV32KqA2rGC/DT0dIWx80mDAAv4og0LmMdS0CI+WTlV7G/99Ea4zzr5G46hDfrUdLVP7EehLrEK+/E3iEK9u77Z/2efGI6DfKBkui68TERir9PDDnld4qeLRtim6nx50ny3wg+ISyzvzul+EzQyA1paPAvRAN2S4xSazc3U/+AMfQIDAQAB");
        m.put("dh_public_b64", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHiegwSZcBlcm7RThKzBDLg1iCdXBMpxoxau1ZP0yPYsbADo6+dJAvpcn29Im3Z/QuO59vSCGmogfeEKoC3xA2zkKHbi2dyIhqinkdgcL4hmIavEnGh6CM0BsbNq0WbNhK3bmK+TPSgLMPlDG5h5e0ok4WeILF2qV+Zw1KJOu6HKHB2V4E0BjdRPVumeOJ1ZSzRJ5TDT6TH55BfDq5dHoxXWhqyA92XuFblYkS/meNxWnKVHtongtAwkkypBX6gqdw==");
        m.put("nonce1_b64", "JxrLe1stN7vA4JqFzVmQCg==");
        m.put("signature_b64", "ORObOeixthhn9C1Px7C6kI3/IvL9jw9d2aRgrYmXjOAqQstQ17Q0iucIKyD2UqwfgmX5LC7EBEWtTKajkr4tSuDqlMMnnh2/FlOAj5lqx2TEDotEakkbvQdM3acOhOxQHeVCHh+MdhG7+alve4uy8lRRoJsDR0tg6qw7gUuySjynjVMwsU956XlmFPsR8Pn6vTsMngKYCVkuiHiFunLh0FkyMqkGKvWdQie5zQAIbJdfIEijlAQgj9fmjmfYVqBwpQgtR9KNsaqJuSznNZeRGPbSZCb8fN6/g3R66hs3WdUDpdSc7o0PDG5zBxuvB7qnlKKNQb7xM5LFf3UYZSP/fg==");
        return m;
    }

    private static Map<String, Object> buildServerHello() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("type", "SERVER_HELLO");
        m.put("proto_ver", "1.0");
        m.put("peer_name", "java-peer");
        m.put("peer_id", "130b2fc830101cd795423eb3cea66a9677d0387a2f02cd6d4d1cfa447fd95eb2");
        m.put("rsa_public_key_der_b64", "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1lNKOeiJWah0+U5NXyRQTe9B7rfJw2kVfPID3ptkZc5UIgjri2jtkDSP37IUoKPckFd0dORlDz0plv2Ajgd6v1ezSi+7CdQfKfZ4dxm7NBZmU4nZQGrpxwPFOGTkkU6/FgolHDhan8+lxUMl77nYAnOC6dGiJe6DkIIIPUIHEC8XNmiDqaWmviN9JlNhxZK8Y4yeKL00vYX3S2kWCT3hNyBvW7+VzaSACzG+cRDUFwXlMg+tyd9gjhvd0ugXAIyR/Rr6JS0/Hn4SJr4P5N0V89rGyD8uvxrHaontb9pPkBFjUpcmNzliL/d7lFK6F3YYPrSL2f7ePsK8oG9gthCDLwIDAQAB");
        m.put("dh_public_b64", "wAbjZ6yyYh6NUleR2GwCx5J5MxZ1/eWt2y/9a5G2eaQHVgXbtmHlWhgCMipHbk+ljPaObSxPTSOIPyP0YDVpz7keDL9Rhqd3sD6yvpEhRPTFNTcuPwfl2V6+Dg4169nWYBpXOuDhpBN7fGqcrZVQtY+R4JSnEuplX4j/RaElB3MFpUVNX4Nzu1GrT9/yyW6S/Wu70Aokx6azH58K6ZVfs+pY33pWAPVGFQy44Sw/VkOedfRMn8SG113qoG5E9xp9");
        m.put("nonce2_b64", "AQIDBAUGBwgJCgsMDQ4PEA==");
        m.put("client_nonce1_b64", "ERITFBUWFxgZGhscHR4fIA==");
        m.put("signature_b64", "D5kUDZiHWW0rPVH2L6vu1R/2fEiMN7CGhY6CNHEdxtD6ssibJkufWgf3IoiJy8UC+2hcnPTw7S74AIyrMCJV/CFUGUbPZFwgbtG0tU2UFtr9Xx4+nKMLx38G++fyBpUutoB0oPJ0qh0qWog7Qc4RntQQMxTfbiXwGnzMl60A1F/H5UxMGXvRkodctNieYeCL3Aw2TPwAeGVulXlkLdgdPmFkopp0bhRuGK5mZI4H77zIdx5gsDvjERThpkiwTu6MMnXhPcuuesA0qhvrgS5Ego/0ImjE1el5biAJ6+2jBijq6UwRQO2lbOa+m0Dyc4wk1dMtzWpNykPWmHKIQTmmJA==");
        return m;
    }

    @Test
    public void testTranscriptHashFixed() {
        byte[] transcript = HandshakeUtil.transcriptHash(CLIENT_HELLO, SERVER_HELLO);
        assertNotNull(transcript);
        assertEquals(32, transcript.length);
        System.out.println("transcript_hash_b64 = " + Base64.getEncoder().encodeToString(transcript));
    }

    @Test
    public void testSessionKeyDerivationFromFixedVectors() {
        byte[] transcript = HandshakeUtil.transcriptHash(CLIENT_HELLO, SERVER_HELLO);

        // Verify HKDF derivation with a dummy shared secret
        byte[] dummyShared = new byte[256];
        Map<String, byte[]> keys = HkdfUtil.deriveSessionMaterial(dummyShared, transcript);

        assertNotNull(keys.get("client_to_server_key"));
        assertNotNull(keys.get("server_to_client_key"));
        assertNotNull(keys.get("session_id_material"));

        assertEquals(32, keys.get("client_to_server_key").length);
        assertEquals(32, keys.get("server_to_client_key").length);
        assertEquals(16, keys.get("session_id_material").length);

        // Keys must differ
        assertFalse(java.util.Arrays.equals(
                keys.get("client_to_server_key"),
                keys.get("server_to_client_key")
        ));
    }
}
