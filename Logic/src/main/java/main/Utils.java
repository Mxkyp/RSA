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
  }
