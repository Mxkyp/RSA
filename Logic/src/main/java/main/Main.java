package main;

import java.util.Scanner;

public class Main {
    public static void main(String[] args) {

/*
        try {
            Scanner scanner = new Scanner(System.in);

            System.out.println("Enter key size (512, 1024, 2048, 4096): ");
            int keySize = scanner.nextInt();
            scanner.nextLine();

            RSAKeyPair keyPair = RSAKeyGenerator.generateKeyPair(keySize);

            System.out.println("\nRSA KEYS (" + keySize + " bit)");
            System.out.println("Public key e: " + keyPair.getPublicKey().getE().toString(16));
            System.out.println("Private key d: " + keyPair.getPrivateKey().getD().toString(16));
            System.out.println("MOD N: " + keyPair.getPublicKey().getN().toString(16));

            System.out.println("\nEnter message: ");
            String message = scanner.nextLine();

            String encrypted = RSAEncryptor.encrypt(message.getBytes(), keyPair.getPublicKey());
            System.out.println("Encrypted message (HEX): " + encrypted);

            byte[] decrypted = RSADecryptor.decrypt(encrypted, keyPair.getPrivateKey());
            String decryptedMessage = new String(decrypted);
            System.out.println("Decrypted message: " + decryptedMessage);

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
*/
    }
}