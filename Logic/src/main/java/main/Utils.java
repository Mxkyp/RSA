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
    // We need an extra byte for the separator (0x00) so the padding length calculation changes:
    int paddingLength = keySize - messageLength - 3;  // 3 bytes: 0x00, 0x02, and the separator 0x00

    if (paddingLength < 8) {
      throw new IllegalArgumentException("Message is too large for the RSA key size.");
    }

    byte[] padding = new byte[paddingLength];
    SecureRandom random = new SecureRandom();
    random.nextBytes(padding);
    for (int i = 0; i < padding.length; i++) {
      if (padding[i] == 0) {
        padding[i] = (byte) 0x01;
      }
    }

    byte[] paddedMessage = new byte[keySize];
    paddedMessage[0] = 0x00;      // First byte: 0x00
    paddedMessage[1] = 0x02;      // Second byte: 0x02

    // Copy the padding bytes
    System.arraycopy(padding, 0, paddedMessage, 2, paddingLength);

    // Insert the separator 0x00
    paddedMessage[2 + paddingLength] = 0x00;

    // Copy the message after the separator
    System.arraycopy(message, 0, paddedMessage, 3 + paddingLength, messageLength);

    return paddedMessage;
  }

  // Method to manually remove PKCS#1 v1.5 padding from a message
  public static byte[] removePKCS1v15Padding(byte[] paddedMessage) {
    // Check for null and minimum length (at least 11 bytes: 2 header + 8 padding + 1 separator)
    if (paddedMessage == null || paddedMessage.length < 11) {
      throw new IllegalArgumentException("Invalid padded message: too short");
    }

    // Verify the header bytes
    if (paddedMessage[0] != 0x00 || paddedMessage[1] != 0x02) {
      throw new IllegalArgumentException("Invalid PKCS#1 v1.5 padding");
    }

    // Find the 0x00 separator while ensuring we don't go out of bounds
    int paddingStartIndex = 2;
    while (paddingStartIndex < paddedMessage.length && paddedMessage[paddingStartIndex] != 0x00) {
      paddingStartIndex++;
    }

    // If no 0x00 was found or if padding is too short
    if (paddingStartIndex == paddedMessage.length || paddingStartIndex < 10) { // must have at least 8 padding bytes
      throw new IllegalArgumentException("Invalid PKCS#1 v1.5 padding structure");
    }

    // The actual message starts after the 0x00 separator
    return Arrays.copyOfRange(paddedMessage, paddingStartIndex + 1, paddedMessage.length);
  }


  }
