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

    /**
     * Applies PKCS7 padding to a given byte array.
     * If the input length is not a multiple of the block size, it adds padding bytes
     * where each byte value represents the total number of padding bytes.
     *
     * @param data      The input data to be padded.
     * @param blockSize The block size (typically 16 bytes for main.AES).
     * @return A new byte array with PKCS7 padding applied.
     */
    public static byte[] padPKCS7(byte[] data, int blockSize) {
        int paddingLength = blockSize - (data.length % blockSize);
        byte[] paddedData = new byte[data.length + paddingLength];

        // Copy original data
        System.arraycopy(data, 0, paddedData, 0, data.length);

        // Fill padding bytes with the padding length
        for (int i = data.length; i < paddedData.length; i++) {
            paddedData[i] = (byte) paddingLength;
        }
        return paddedData;
    }

    /**
     * Removes PKCS7 padding from a given byte array.
     * This method checks the padding format and trims it from the end of the data.
     *
     * @param data The input byte array with padding.
     * @return The original data without padding.
     * @throws IllegalArgumentException if padding is invalid or corrupted.
     */
    public static byte[] removePKCS7Padding(byte[] data) {
        if (data.length == 0) {
            throw new IllegalArgumentException("Error: Data is empty.");
        }

        int paddingLength = data[data.length - 1] & 0xFF; // Extract padding length

        // Validate padding length
        if (paddingLength < 1 || paddingLength > 16) {
            throw new IllegalArgumentException("Error: Invalid PKCS7 padding.");
        }

        // Ensure that all padding bytes match the expected value
        for (int i = 1; i <= paddingLength; i++) {
            if (data[data.length - i] != (byte) paddingLength) {
                throw new IllegalArgumentException("Error: Corrupted PKCS7 padding.");
            }
        }


        // Return the original data without padding
        return Arrays.copyOfRange(data, 0, data.length - paddingLength);
    }

    /**
     * Generates a random main.AES key of the specified size.
     *
     * @param keySize The size of the key in bits (128, 192, or 256).
     * @return A randomly generated key as a byte array.
     */
    public static byte[] generateRandomKey(int keySize) {
        byte[] key = new byte[keySize / 8]; // Convert bits to bytes
        new SecureRandom().nextBytes(key); // Generate secure random bytes
        return key;
    }

    /**
     * Converts a byte array into a hexadecimal string representation.
     * Each byte is represented by two hexadecimal characters.
     *
     * @param bytes The byte array to be converted.
     * @return A string containing the hexadecimal representation of the byte array.
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02X", b)); // Format each byte as a 2-character hex string
        }
        return hexString.toString();
    }

    /**
     * Converts a Hexadecimal string into a byte array representation.
     * Each byte is represented by two hexadecimal characters.
     *
     * @param hex The byte array to be converted.
     * @return A byte array equal to the hexadecimal representation.
     */
    public static Byte[] hexToBytes(String hex) {
        List<String> substrings = splitString(hex, 2);  // Split into substrings of length 2
        List<Byte> tempKey = new ArrayList<>();
        int counter = 0;
        for (String s : substrings) {
            tempKey.add((byte) Integer.parseInt(s, 16));
        }

        return tempKey.toArray(new Byte[0]);
    }

    public static List<String> splitString(String str, int length) {
        List<String> result = new ArrayList<>();

        for (int i = 0; i < str.length(); i += length) {
            result.add(str.substring(i, Math.min(i + length, str.length())));
        }
        return result;
    }
}
