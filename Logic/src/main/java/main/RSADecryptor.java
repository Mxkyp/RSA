package main;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;

import static main.Utils.*;

public class RSADecryptor {
    public static byte[] decrypt(String encryptedMessage, RSAPrivateKey privateKey) throws Exception {
        byte[] encryptedBytes = Utils.hexToBytes(encryptedMessage);
        BigInteger c = new BigInteger(1, encryptedBytes);
        BigInteger m = c.modPow(privateKey.getD(), privateKey.getN());
        return m.toByteArray();
    }

    public static byte[] decrypt(byte[] encryptedBytes, RSAPrivateKey privateKey) throws Exception {
        BigInteger c = new BigInteger(1, encryptedBytes);
        BigInteger m = c.modPow(privateKey.getD(), privateKey.getN());
        return m.toByteArray();
    }

    public static byte[] decryptMessage(String encryptedMessage, RSAPrivateKey privateKey) throws Exception {
        byte[] encryptedBytes = Utils.hexToBytes(encryptedMessage);
        ArrayList<Byte> decryptedBytes = new ArrayList<>(encryptedBytes.length / 2);
        ByteArrayInputStream inStream = new ByteArrayInputStream(encryptedBytes);
        byte[] buff = new byte[64];
        int n = 0;
        while((n = inStream.readNBytes(buff,0, 64)) > 0) {
            byte[] chunk = Arrays.copyOf(buff, n);
            byte[] decryptedChunk = decrypt(chunk, privateKey);
            appendBytes(decryptedBytes, decryptedChunk, decryptedChunk.length);
        }
        return getSimpleByteArray(decryptedBytes);
    }
}
