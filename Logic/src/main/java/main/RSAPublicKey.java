package main;

import java.math.BigInteger;

public class RSAPublicKey {
    private final BigInteger n;
    private final BigInteger e;

    public RSAPublicKey(BigInteger n, BigInteger e) {
        this.n = n;
        this.e = e;
    }

    public BigInteger getN() {
        return n;
    }

    public BigInteger getE() {
        return e;
    }
}