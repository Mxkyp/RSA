package main;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

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

    public static byte[] decryptMessage(String encryptedHex, RSAPrivateKey privateKey) throws Exception {
        byte[] encryptedBytes = Utils.hexToBytes(encryptedHex);
        int chunkSize = (privateKey.getN().bitLength() + 7) / 8; // RSA block size in bytes

        List<Byte> decryptedBytes = new ArrayList<>();

        for (int i = 0; i < encryptedBytes.length; i += chunkSize) {
            int len = Math.min(chunkSize, encryptedBytes.length - i);
            byte[] chunk = new byte[len];
            System.arraycopy(encryptedBytes, i, chunk, 0, len);

            byte[] decryptedChunk = decrypt(chunk, privateKey);

            // Handle possible leading zero byte in BigInteger.toByteArray()
            if (decryptedChunk.length > 1 && decryptedChunk[0] == 0) {
                byte[] tmp = new byte[decryptedChunk.length - 1];
                System.arraycopy(decryptedChunk, 1, tmp, 0, tmp.length);
                decryptedChunk = tmp;
            }

            for (byte b : decryptedChunk) {
                decryptedBytes.add(b);
            }
        }

        // Convert List<Byte> back to byte[]
        byte[] result = new byte[decryptedBytes.size()];
        for (int i = 0; i < decryptedBytes.size(); i++) {
            result[i] = decryptedBytes.get(i);
        }

        return result;
    }

}
