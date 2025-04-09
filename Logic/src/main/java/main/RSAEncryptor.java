package main;

import java.io.ByteArrayInputStream;
import java.lang.reflect.Array;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static main.Utils.addPKCS1Padding;


public class RSAEncryptor {


  // Example encryption method that takes a block and returns the encrypted block.
  // This method should internally work with RSA (for example, via BigInteger.modPow()).
  private static byte[] encrypt(byte[] paddedChunk, RSAPublicKey publicKey) throws Exception {
    BigInteger m = new BigInteger(1, paddedChunk);
    BigInteger c = m.modPow(publicKey.getE(), publicKey.getN());
    byte[] encrypted = c.toByteArray();

    // Ensure the encrypted byte array has the full key size
    int keyByteSize = (publicKey.getN().bitLength() + 7) / 8;
    if (encrypted.length < keyByteSize) {
      byte[] tmp = new byte[keyByteSize];
      System.arraycopy(encrypted, 0, tmp, keyByteSize - encrypted.length, encrypted.length);
      encrypted = tmp;
    }
    return encrypted;
  }


  /**
   * Encrypts the message by first padding each chunk according to PKCS#1 v1.5, then encrypting.
   */
  public static byte[] encryptMessage(byte[] message, RSAPublicKey publicKey) throws Exception {
    int keyByteSize = (publicKey.getN().bitLength() + 7) / 8;
    // Maximum message length in one block is keyByteSize - 11 bytes for PKCS#1 v1.5
    int maxMessageLength = keyByteSize - 11;

    List<Byte> encryptedBytes = new ArrayList<>();
    for (int i = 0; i < message.length; i += maxMessageLength) {
      int chunkSize = Math.min(maxMessageLength, message.length - i);
      byte[] chunk = new byte[chunkSize];
      System.arraycopy(message, i, chunk, 0, chunkSize);

      // Add PKCS#1 v1.5 padding to the chunk
      byte[] paddedChunk = addPKCS1Padding(chunk, keyByteSize);

      // Encrypt the padded chunk
      byte[] encryptedChunk = encrypt(paddedChunk, publicKey);

      // Collect encrypted result
      for (byte b : encryptedChunk) {
        encryptedBytes.add(b);
      }
    }

    // Convert List<Byte> to byte[]
    byte[] result = new byte[encryptedBytes.size()];
    for (int i = 0; i < encryptedBytes.size(); i++) {
      result[i] = encryptedBytes.get(i);
    }
    return result;
  }
}