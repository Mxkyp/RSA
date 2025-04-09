package main;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static main.Utils.*;

public class RSADecryptor {
    // Example decryption method that takes a block and returns the decrypted padded block.
    private static byte[] decrypt(byte[] encryptedChunk, RSAPrivateKey privateKey) throws Exception {
        BigInteger c = new BigInteger(1, encryptedChunk);
        BigInteger m = c.modPow(privateKey.getD(), privateKey.getN());
        byte[] padded = m.toByteArray();
        // Remove potential leading zero that BigInteger.toByteArray() may add
        if (padded.length > 1 && padded[0] == 0x00) {
            byte[] tmp = new byte[padded.length - 1];
            System.arraycopy(padded, 1, tmp, 0, tmp.length);
            padded = tmp;
        }
        return padded;
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

    /**
     * Decrypts the encrypted bytes by processing each chunk, then removes the PKCS#1 v1.5 padding.
     */
    public static byte[] decryptMessage(byte[] encryptedBytes, RSAPrivateKey privateKey) throws Exception {
        int keyByteSize = (privateKey.getN().bitLength() + 7) / 8; // Full RSA block size in bytes

        List<Byte> decryptedBytes = new ArrayList<>();
        for (int i = 0; i < encryptedBytes.length; i += keyByteSize) {
            byte[] chunk = new byte[keyByteSize];
            System.arraycopy(encryptedBytes, i, chunk, 0, keyByteSize);

            byte[] paddedDecryptedChunk = decrypt(chunk, privateKey);

            // Remove PKCS#1 padding from the decrypted chunk
            byte[] chunkWithoutPadding = removePKCS1Padding(paddedDecryptedChunk);

            for (byte b : chunkWithoutPadding) {
                decryptedBytes.add(b);
            }
        }

        // Convert List<Byte> to byte[]
        byte[] result = new byte[decryptedBytes.size()];
        for (int i = 0; i < decryptedBytes.size(); i++) {
            result[i] = decryptedBytes.get(i);
        }
        return result;
    }
}
