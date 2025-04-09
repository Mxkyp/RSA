package main;

import java.util.Scanner;

public class Main {
    public static void main(String[] args) {

        /*
        try {
            Scanner scanner = new Scanner(System.in);


            RSAKeyPair keyPair = RSAKeyGenerator.generateKeyPair(512);

            System.out.println("\nRSA KEYS (" + 512 + " bit)");
            System.out.println("Public key e: " + keyPair.getPublicKey().getE().toString(16));
            System.out.println("Private key d: " + keyPair.getPrivateKey().getD().toString(16));
            System.out.println("MOD N: " + keyPair.getPublicKey().getN().toString(16));

            String message = "FTIMS IV C1 BA/3 your course id:NPEM-HTRFdon't transfer grades";

            String encrypted = RSAEncryptor.encryptMessage(message.getBytes(), keyPair.getPublicKey());
            System.out.println("Encrypted message (HEX): " + encrypted);

            byte[] decrypted = RSADecryptor.decryptMessage(encrypted, keyPair.getPrivateKey());
            String decryptedMessage = new String(decrypted);
            System.out.println("Decrypted message: " + decryptedMessage);

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }

         */
    }
}