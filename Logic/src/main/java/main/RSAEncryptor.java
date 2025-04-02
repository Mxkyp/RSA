package main;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.util.ArrayList;

import static main.Utils.*;

public class RSAEncryptor {
    public static String encrypt(byte[] message, RSAPublicKey publicKey) throws Exception {
        BigInteger m = new BigInteger(1, message);
        if (m.compareTo(publicKey.getN()) > 0) {
            throw new IllegalArgumentException("Message too large for RSA key size");
        }

        BigInteger c = m.modPow(publicKey.getE(), publicKey.getN());
        return Utils.bytesToHex(fixBlockSize(c.toByteArray(), 64));
    }

    public static String encryptMessage(byte[] message, RSAPublicKey publicKey) throws Exception {
        StringBuilder encryptedMessage = new StringBuilder(message.length);
        ByteArrayInputStream data = new ByteArrayInputStream(message);
        byte[] buff = new byte[64];
        int n = 0;
        while((n = data.readNBytes(buff,0,64)) > 0) {
            encryptedMessage.append(encrypt(buff, publicKey));
        }
        return encryptedMessage.toString();
    }

}