package main;

import java.math.BigInteger;

public class RSADecryptor {
    public static byte[] decrypt(String encryptedMessage, RSAPrivateKey privateKey) throws Exception {
        byte[] encryptedBytes = Utils.hexToBytes(encryptedMessage);
        BigInteger c = new BigInteger(1, encryptedBytes);
        BigInteger m = c.modPow(privateKey.getD(), privateKey.getN());
        return m.toByteArray();
    }
}
