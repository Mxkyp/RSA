package main;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Utility class for common main.AES-related operations.
 * This includes padding, key generation, and hex encoding.
 */
public class Utils {
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


  public static byte[] fixBlockSize(byte[] chunk, int expectedSize) {
    if (chunk.length > expectedSize) {
      // Trim leading zero if the block is too large
      int offset = chunk.length - expectedSize;
      byte[] trimmed = new byte[expectedSize];
      System.arraycopy(chunk, offset, trimmed, 0, expectedSize);
      chunk = trimmed;
    }
    return chunk;
  }

  }
