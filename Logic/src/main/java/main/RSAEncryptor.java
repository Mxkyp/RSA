package main;

import java.math.BigInteger;

public class RSAEncryptor {
    public static String encrypt(byte[] message, RSAPublicKey publicKey) throws Exception {
        BigInteger m = new BigInteger(1, message);
        if (m.compareTo(publicKey.getN()) >= 0) {
            throw new IllegalArgumentException("Message too large for RSA key size");
        }

        BigInteger c = m.modPow(publicKey.getE(), publicKey.getN());
        return Utils.bytesToHex(c.toByteArray());
    }
}