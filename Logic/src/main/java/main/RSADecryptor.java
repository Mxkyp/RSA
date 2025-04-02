package main;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
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

    public static byte[] decryptMessage(String encryptedMessage, RSAPrivateKey privateKey) throws Exception {
        byte[] encryptedBytes = Utils.hexToBytes(encryptedMessage);
        return decryptMessage(encryptedBytes, privateKey);
    }

    public static byte[] decryptMessage(byte[] encryptedBytes, RSAPrivateKey privateKey) throws Exception {
        ArrayList<Byte> decryptedBytes = new ArrayList<>(encryptedBytes.length);
        ByteArrayInputStream encrypedData = new ByteArrayInputStream(encryptedBytes);
        byte[] buff = new byte[64];
        int n = 0;
        while((n = encrypedData.readNBytes(buff,0,64)) > 0) {
            byte[] decryptedChunk = decrypt(buff, privateKey);
            //decryptedChunk = fixBlockSize(decryptedChunk, 64);
            System.out.println(decryptedChunk.length);
            appendBytes(decryptedBytes, decryptedChunk, decryptedChunk.length);
        }
        return getSimpleByteArray(decryptedBytes);
    }

}
