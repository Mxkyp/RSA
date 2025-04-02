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


  // Method to manually apply PKCS#1 v1.5 padding to a message
  public static byte[] applyPKCS1v15Padding(byte[] message, int keySize) {
    int messageLength = message.length;
    int paddingLength = keySize - messageLength - 3;
    if (paddingLength < 8) {
      //throw new IllegalArgumentException("Message is too large for the RSA key size.");
    }

    // 0x00 0x02 (Padding header)
    byte[] padding = new byte[paddingLength];

    // Fill padding with non-zero random bytes
    random.nextBytes(padding);
    for (int i = 0; i < padding.length; i++) {
      if (padding[i] == 0) {
        padding[i] = (byte) 0x01;  // Ensure that padding does not contain 0x00 bytes
      }
    }

    // Combine padding header, padding, and message
    byte[] paddedMessage = new byte[keySize];
    paddedMessage[0] = 0x00;  // First byte (0x00)
    paddedMessage[1] = 0x02;  // Second byte (0x02)

    // Copy the padding into the array
    System.arraycopy(padding, 0, paddedMessage, 2, padding.length);

    // Copy the message at the end
    System.arraycopy(message, 0, paddedMessage, 2 + padding.length, message.length);

    return paddedMessage;
  }

  // Method to manually remove PKCS#1 v1.5 padding from a message
  public static byte[] removePKCS1v15Padding(byte[] paddedMessage) {
    if (paddedMessage[0] != 0x00 || paddedMessage[1] != 0x02) {
      throw new IllegalArgumentException("Invalid PKCS#1 v1.5 padding");
    }

    int paddingStartIndex = 2;
    while (paddedMessage[paddingStartIndex] != 0x00) {
      paddingStartIndex++;
    }

    // The actual message starts after the padding and the 0x00 separator
    byte[] message = Arrays.copyOfRange(paddedMessage, paddingStartIndex + 1, paddedMessage.length);
    return message;
  }


  }
