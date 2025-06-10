import java.math.BigInteger;
import java.security.SecureRandom;
import java.nio.file.*;
import java.io.*;

public class RSA {
    private static final int BIT_LENGTH = 512;
    private static BigInteger p, q, n, phi, e, d;

    public static void main(String[] args) {
        generateKeys();

        String message = readFromFile("message.txt");
        if (message == null || message.trim().isEmpty()) {
            System.out.println("The input file is empty. Aborting encryption.");
            return;
        }

        System.out.println("Original message: " + message);

        BigInteger[] encrypted = encrypt(message);
        writeEncryptedToFile(encrypted, "encrypted.txt");
        System.out.println("Encrypted text saved to encrypted.txt");

        BigInteger[] encryptedFromFile = readEncryptedFromFile("encrypted.txt");
        if (encryptedFromFile == null) return;

        String decrypted = decrypt(encryptedFromFile);
        writeToFile("decrypted.txt", decrypted);
        System.out.println("Decrypted message saved to decrypted.txt");
    }

    // Key generation
    private static void generateKeys() {
        SecureRandom random = new SecureRandom();
        p = BigInteger.probablePrime(BIT_LENGTH, random);
        q = BigInteger.probablePrime(BIT_LENGTH, random);
        n = p.multiply(q);
        phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        e = BigInteger.valueOf(3);
        while (!gcd(e, phi).equals(BigInteger.ONE)) {
            e = e.add(BigInteger.TWO);
        }

        d = modInverse(e, phi);
        System.out.println("Public Key: (" + e + ", " + n + ")");
        System.out.println("Private Key: (" + d + ", " + n + ")");
    }

    private static BigInteger[] encrypt(String message) {
        BigInteger[] cipher = new BigInteger[message.length()];
        for (int i = 0; i < message.length(); i++) {
            cipher[i] = modExp(BigInteger.valueOf(message.charAt(i)), e, n);
        }
        return cipher;
    }

    private static String decrypt(BigInteger[] cipher) {
        StringBuilder result = new StringBuilder();
        for (BigInteger c : cipher) {
            result.append((char) modExp(c, d, n).intValue());
        }
        return result.toString();
    }

    private static BigInteger modExp(BigInteger base, BigInteger exp, BigInteger mod) {
        BigInteger result = BigInteger.ONE;
        base = base.mod(mod);
        while (exp.compareTo(BigInteger.ZERO) > 0) {
            if (exp.mod(BigInteger.TWO).equals(BigInteger.ONE))
                result = result.multiply(base).mod(mod);
            base = base.multiply(base).mod(mod);
            exp = exp.shiftRight(1);
        }
        return result;
    }

    private static BigInteger modInverse(BigInteger a, BigInteger m) {
        BigInteger m0 = m, x0 = BigInteger.ZERO, x1 = BigInteger.ONE;
        while (a.compareTo(BigInteger.ONE) > 0) {
            BigInteger q = a.divide(m);
            BigInteger t = m;
            m = a.mod(m); a = t;
            t = x0;
            x0 = x1.subtract(q.multiply(x0));
            x1 = t;
        }
        if (x1.compareTo(BigInteger.ZERO) < 0)
            x1 = x1.add(m0);
        return x1;
    }

    private static BigInteger gcd(BigInteger a, BigInteger b) {
        while (!b.equals(BigInteger.ZERO)) {
            BigInteger temp = b;
            b = a.mod(b);
            a = temp;
        }
        return a;
    }

    // File I/O
    private static String readFromFile(String filename) {
        try {
            return Files.readString(Path.of(filename)).trim();
        } catch (IOException e) {
            System.out.println("Error reading " + filename + ": " + e.getMessage());
            return null;
        }
    }

    private static void writeToFile(String filename, String content) {
        try {
            Files.writeString(Path.of(filename), content);
        } catch (IOException e) {
            System.out.println("Error writing to " + filename + ": " + e.getMessage());
        }
    }

    private static void writeEncryptedToFile(BigInteger[] data, String filename) {
        try (PrintWriter writer = new PrintWriter(filename)) {
            for (BigInteger b : data) {
                writer.println(b.toString());
            }
        } catch (IOException e) {
            System.out.println("Error writing encrypted file: " + e.getMessage());
        }
    }

    private static BigInteger[] readEncryptedFromFile(String filename) {
        try {
            return Files.lines(Path.of(filename))
                    .map(BigInteger::new)
                    .toArray(BigInteger[]::new);
        } catch (IOException e) {
            System.out.println("Error reading encrypted file: " + e.getMessage());
            return null;
        }
    }
}
