package com.example.signing;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

/**
 * Requests a signature over a file from the Signing API stub and verifies it.
 *
 * Usage: mvnw -q compile exec:java -Dexec.args="path/to/file"
 * Needs CSC_CLIENT_ID and CSC_CLIENT_SECRET; CSC_BASE_URL is optional.
 */
public class Main {

    private static final String DEFAULT_BASE_URL = "https://trust-driver-stub-hash-signing.cleverbase.com";

    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("Usage: mvnw -q compile exec:java -Dexec.args=\"<file to sign>\"");
            System.exit(64);
        }
        try {
            boolean valid = run(Path.of(args[0]));
            System.exit(valid ? 0 : 1);
        } catch (Exception e) {
            System.err.println("ERROR: " + e.getMessage());
            System.exit(2);
        }
    }

    static boolean run(Path file) throws Exception {
        if (!Files.isRegularFile(file)) {
            throw new IllegalArgumentException("file not found: " + file.toAbsolutePath());
        }
        byte[] document = Files.readAllBytes(file);

        StubClient client = new StubClient(
                env("CSC_BASE_URL", DEFAULT_BASE_URL),
                env("CSC_CLIENT_ID", null),
                env("CSC_CLIENT_SECRET", null));

        // 1. Get the signer's certificate
        String serviceToken = client.serviceToken();
        String credentialId = client.firstCredentialId(serviceToken);
        List<X509Certificate> chain = client.certificateChain(serviceToken, credentialId);
        X509Certificate cert = chain.get(0);

        System.out.println("Signer's certificate (credential " + credentialId + ")");
        System.out.println("  Subject:  " + cert.getSubjectX500Principal());
        System.out.println("  Issuer:   " + cert.getIssuerX500Principal());
        System.out.println("  Valid:    " + cert.getNotBefore() + "  to  " + cert.getNotAfter());
        System.out.println("  Key:      " + cert.getPublicKey().getAlgorithm() + ", chain of " + chain.size() + " certificate(s)");

        // 2. Get a signature over the file's SHA-256 hash
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(document);
        String sad = client.sad(credentialId, hash);
        Date signingTime = new Date();
        byte[] signature = client.signHash(serviceToken, credentialId, sad, hash,
                SignatureVerifier.cscSignAlgoFor(cert.getPublicKey()));

        System.out.println();
        System.out.println("Signed " + file + " (" + document.length + " bytes), signature is " + signature.length + " bytes");

        // 3. Verify it
        SignatureVerifier.Result result = SignatureVerifier.verify(document, signature, cert.getPublicKey());
        SignatureVerifier.Result chainResult = SignatureVerifier.checkChain(chain, signingTime);

        // The same check on a file with one byte added, and with Pieter's input (the hash instead of the file)
        byte[] tampered = Arrays.copyOf(document, document.length + 1);
        SignatureVerifier.Result tamperedResult = SignatureVerifier.verify(tampered, signature, cert.getPublicKey());
        SignatureVerifier.Result hashAsInput = SignatureVerifier.verify(hash, signature, cert.getPublicKey());

        System.out.println();
        System.out.println("Verification");
        System.out.println("  Signature over your file:      " + result);
        System.out.println("  Certificate chain:             " + chainResult);
        System.out.println("  Same file, one byte added:     " + tamperedResult);
        System.out.println("  Hash given as input (Pieter):  " + hashAsInput);
        System.out.println();
        System.out.println("Note: the stub's CA is not trusted, so this is not a qualified signature.");

        return result.valid();
    }

    private static String env(String name, String defaultValue) {
        String value = System.getenv(name);
        if (value != null && !value.isBlank()) {
            return value;
        }
        if (defaultValue == null) {
            throw new IllegalStateException("environment variable " + name + " is not set (see README)");
        }
        return defaultValue;
    }
}
