package main;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;

import static main.Utils.*;

public class RSAEncryptor {
    public static String encrypt(byte[] message, RSAPublicKey publicKey) throws Exception {
        BigInteger m = new BigInteger(1, message);
        if (m.compareTo(publicKey.getN()) > 0) {
            throw new IllegalArgumentException("Message too large for RSA key size");
        }

        BigInteger c = m.modPow(publicKey.getE(), publicKey.getN());
        return Utils.bytesToHex(c.toByteArray());
    }

    public static String encryptMessage(byte[] message, RSAPublicKey publicKey) throws Exception {
        StringBuilder encryptedMessage = new StringBuilder(message.length);
        ByteArrayInputStream data = new ByteArrayInputStream(message);
        byte[] buff = new byte[53];
        int n = 0;
        while((n = data.readNBytes(buff,0,53)) > 0) {
            byte[] chunk = Arrays.copyOf(buff, n);
            byte[] paddedMessage = applyPKCS1v15Padding(chunk, 64);
            encryptedMessage.append(encrypt(paddedMessage, publicKey));
        }
        return encryptedMessage.toString();
    }

}