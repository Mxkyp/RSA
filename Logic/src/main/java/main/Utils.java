package main;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Utility class for common main.RSA-related operations.
 * This includes padding, key generation, and hex encoding.
 */
public class Utils {

  private static final SecureRandom random = new SecureRandom();

      public static String bytesToHex(byte[] bytes) {
          StringBuilder hexString = new StringBuilder();
          for (byte b : bytes) {
              hexString.append(String.format("%02X", b));
          }
          return hexString.toString();
      }

      public static byte[] hexToBytes(String hex) {
          int len = hex.length();
          byte[] data = new byte[len / 2];
          for (int i = 0; i < len; i += 2) {
              data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                      + Character.digit(hex.charAt(i + 1), 16));
          }
          return data;
      }

    public static void appendBytes(ArrayList<Byte> decryptedBytes, byte[] buff, final int n) {
      for(int i = 0; i < n ; i++) {
        decryptedBytes.add(buff[i]);
      }
    }

    public static byte[] getSimpleByteArray(ArrayList<Byte> array){
      byte[] arr = new byte[array.size()];
      for(int i = 0; i < array.size(); i++) {
        arr[i] = array.removeFirst();
      }

      return arr;
    }


  public static byte[] addPKCS1Padding(byte[] message, int blockSize) throws Exception {
    if (message.length > blockSize - 11) {
      throw new Exception("Message too long for RSA encryption");
    }
    byte[] padded = new byte[blockSize];
    padded[0] = 0x00;
    padded[1] = 0x02;
    SecureRandom random = new SecureRandom();
    int padLength = blockSize - message.length - 3;
    // Fill with nonzero random bytes
    for (int i = 0; i < padLength; i++) {
      byte rand = 0;
      while (rand == 0) {
        rand = (byte) random.nextInt(256);
      }
      padded[i + 2] = rand;
    }
    padded[2 + padLength] = 0x00; // Padding delimiter
    System.arraycopy(message, 0, padded, 3 + padLength, message.length);
    return padded;
  }

  /**
   * Removes PKCS#1 v1.5 padding from a decrypted block.
   */
  public static byte[] removePKCS1Padding(byte[] padded) throws Exception {
    // Check the padding header
    /*
    if (padded[0] != 0x00 || padded[1] != 0x02) {
      throw new Exception("Invalid PKCS#1 padding");
    }
    */
    // Find the zero delimiter marking the end of the padding
    int index = -1;
    for (int i = 2; i < padded.length; i++) {
      if (padded[i] == 0x00) {
        index = i;
        break;
      }
    }
    if (index < 0) {
      throw new Exception("Invalid PKCS#1 padding: no delimiter found");
    }
    int messageLength = padded.length - index - 1;
    byte[] message = new byte[messageLength];
    System.arraycopy(padded, index + 1, message, 0, messageLength);
    return message;
  }
  }
