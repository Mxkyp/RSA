package main;

import java.io.ByteArrayInputStream;
import java.lang.reflect.Array;
import java.math.BigInteger;
import java.util.Arrays;

import static main.Utils.applyPKCS1v15Padding;

public class RSAEncryptor {
    public static String encrypt(byte[] message, RSAPublicKey publicKey) throws Exception {
        BigInteger m = new BigInteger(1, message);
        if (m.compareTo(publicKey.getN()) >= 0) {
            throw new IllegalArgumentException("Message too large for RSA key size");
        }

        BigInteger c = m.modPow(publicKey.getE(), publicKey.getN());
        System.out.println(c.toByteArray().length);
        return Utils.bytesToHex(c.toByteArray());
    }

    public static String encryptMessage(byte[] message, RSAPublicKey publicKey) throws Exception {
        StringBuilder encryptedMessage = new StringBuilder(2 * message.length);
        ByteArrayInputStream inStream = new ByteArrayInputStream(message);
       byte[] buff = new byte[32];
       int n = 0;
       while((n = inStream.readNBytes(buff,0, 32)) > 0) {
           byte[] chunkOG = Arrays.copyOf(buff, n);
           byte[] chunk = applyPKCS1v15Padding(chunkOG, 64);
           System.out.print(Utils.bytesToHex(chunk) + " ");
           encryptedMessage.append(encrypt(chunk, publicKey));
       }
       return encryptedMessage.toString();
    }
}