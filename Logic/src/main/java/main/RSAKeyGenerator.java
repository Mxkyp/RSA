package main;

import java.math.BigInteger;
import java.security.SecureRandom;

public class RSAKeyGenerator {
    private static final SecureRandom random = new SecureRandom();

    public static RSAKeyPair generateKeyPair(int keySizeBits) {
        if (keySizeBits < 512) {
            throw new IllegalArgumentException("Key size must be at least 512 bits");
        }

        int primeSize = keySizeBits / 2;
        BigInteger p = BigInteger.probablePrime(primeSize, random);
        BigInteger q = BigInteger.probablePrime(primeSize, random);

        BigInteger n = p.multiply(q);
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        int eBitLength = keySizeBits / 2;
        BigInteger e = generateE(phi, eBitLength);

        BigInteger d = e.modInverse(phi);

        return new RSAKeyPair(new RSAPublicKey(n, e), new RSAPrivateKey(n, d));
    }

    private static BigInteger generateE(BigInteger phi, int keySizeBits) {
        int eBitLength = Math.max(32, keySizeBits / 4);

        BigInteger e;
        do {
            e = new BigInteger(eBitLength, random);
        } while (e.compareTo(BigInteger.ONE) <= 0 ||
                e.compareTo(phi) >= 0 ||
                !e.gcd(phi).equals(BigInteger.ONE));
        return e;
    }
}