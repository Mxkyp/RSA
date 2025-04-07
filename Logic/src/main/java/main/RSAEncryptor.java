package main;

import java.io.ByteArrayInputStream;
import java.lang.reflect.Array;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static main.Utils.applyPKCS1v15Padding;
import static main.Utils.bytesToHex;

public class RSAEncryptor {

  public static byte[] encrypt(byte[] message, RSAPublicKey publicKey) throws Exception {
    BigInteger m = new BigInteger(1, message);
    if (m.compareTo(publicKey.getN()) >= 0) {
      throw new IllegalArgumentException("Message chunk too large for RSA key size");
    }

    BigInteger c = m.modPow(publicKey.getE(), publicKey.getN());
    return c.toByteArray(); // return raw encrypted bytes
  }

  public static String encryptMessage(byte[] message, RSAPublicKey publicKey) throws Exception {
    int keyLengthBytes = (publicKey.getN().bitLength() - 1) / 8;

    List<Byte> encryptedBytes = new ArrayList<>();
    for (int i = 0; i < message.length; i += keyLengthBytes) {
      int chunkSize = Math.min(keyLengthBytes, message.length - i);
      byte[] chunk = new byte[chunkSize];
      System.arraycopy(message, i, chunk, 0, chunkSize);

      byte[] encryptedChunk = encrypt(chunk, publicKey);
      for (byte b : encryptedChunk) {
        encryptedBytes.add(b);
      }
    }

    // Convert the final List<Byte> to a byte array for hex conversion
    byte[] result = new byte[encryptedBytes.size()];
    for (int i = 0; i < encryptedBytes.size(); i++) {
      result[i] = encryptedBytes.get(i);
    }

    return bytesToHex(result);
  }

}