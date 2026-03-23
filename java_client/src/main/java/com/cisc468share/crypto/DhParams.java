package com.cisc468share.crypto;

import java.math.BigInteger;

public final class DhParams {
    private DhParams() {}

    public static final String GROUP14_PRIME_HEX =
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08" +
            "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD" +
            "3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E" +
            "7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899F" +
            "A5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05" +
            "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C" +
            "62F356208552BB9ED529077096966D670C354E4ABC9804F174" +
            "6C08CA237327FFFFFFFFFFFFFFFF";

    public static final BigInteger GROUP14_P = new BigInteger(GROUP14_PRIME_HEX, 16);
    public static final BigInteger GROUP14_G = BigInteger.valueOf(2L);
    public static final int GROUP14_SIZE_BYTES = (GROUP14_P.bitLength() + 7) / 8;

    public static byte[] intToFixedLengthBytes(BigInteger value) {
        byte[] raw = value.toByteArray();
        if (raw.length == GROUP14_SIZE_BYTES) {
            return raw;
        }
        byte[] out = new byte[GROUP14_SIZE_BYTES];
        if (raw.length > GROUP14_SIZE_BYTES) {
            System.arraycopy(raw, raw.length - GROUP14_SIZE_BYTES, out, 0, GROUP14_SIZE_BYTES);
        } else {
            System.arraycopy(raw, 0, out, GROUP14_SIZE_BYTES - raw.length, raw.length);
        }
        return out;
    }

    public static BigInteger bytesToInt(byte[] data) {
        return new BigInteger(1, data);
    }

    public static boolean isValidPublicValue(BigInteger y) {
        return y.compareTo(BigInteger.valueOf(2L)) >= 0 &&
               y.compareTo(GROUP14_P.subtract(BigInteger.valueOf(2L))) <= 0;
    }
}
