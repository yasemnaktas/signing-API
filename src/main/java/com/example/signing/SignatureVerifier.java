package com.example.signing;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

/**
 * Verifies a signature returned by signHash.
 *
 * signHash signs the SHA-256 hash of the document. Java's "SHA256withRSA" / "SHA256withECDSA"
 * compute that same SHA-256 hash themselves, so you must give them the document bytes. Giving
 * them the hash makes Java hash it a second time, and the check fails. That is Pieter's bug.
 */
public final class SignatureVerifier {

    public record Result(boolean valid, String reason) {
        @Override
        public String toString() {
            return (valid ? "VALID" : "INVALID") + " - " + reason;
        }
    }

    private SignatureVerifier() {
    }

    /** Is {@code signature} a valid signature by {@code publicKey} over {@code document}? */
    public static Result verify(byte[] document, byte[] signature, PublicKey publicKey) {
        String algorithm = javaAlgorithmFor(publicKey);
        if (algorithm == null) {
            return new Result(false, "unsupported key type " + publicKey.getAlgorithm());
        }
        try {
            Signature verifier = Signature.getInstance(algorithm);
            verifier.initVerify(publicKey);
            // Whatever goes into update() is hashed by Java with SHA-256 before the check, so this
            // must be the document. Passing the hash here (Pieter's bug) makes Java hash it twice.
            verifier.update(document);
            return verifier.verify(signature)
                    ? new Result(true, "signature matches this file and the signer's public key (" + algorithm + ")")
                    : new Result(false, "signature does not match: the file was changed, or it was signed with another key");
        } catch (SignatureException e) {
            return new Result(false, "signature bytes are malformed: " + e.getMessage());
        } catch (GeneralSecurityException e) {
            return new Result(false, "could not verify: " + e.getMessage());
        }
    }

    /**
     * Was the signer's certificate issued by the next certificate in the chain, and valid at
     * {@code signingTime}? This proves the chain is consistent, not that it is trusted: for that
     * you would also check the root against the EU trusted list and check revocation.
     */
    public static Result checkChain(List<X509Certificate> chain, Date signingTime) {
        X509Certificate signer = chain.get(0);
        try {
            signer.checkValidity(signingTime);
        } catch (GeneralSecurityException e) {
            return new Result(false, "signer's certificate is not valid at signing time: " + e.getMessage());
        }
        if (chain.size() < 2) {
            return new Result(false, "no issuer certificate in the chain, cannot check who issued it");
        }
        X509Certificate issuer = chain.get(1);
        try {
            signer.verify(issuer.getPublicKey());
        } catch (GeneralSecurityException e) {
            return new Result(false, "signer's certificate was not signed by " + issuer.getSubjectX500Principal());
        }
        return new Result(true, "issued by " + issuer.getSubjectX500Principal() + " and valid at signing time");
    }

    /** The CSC signAlgo OID to send to signHash for this key. */
    public static String cscSignAlgoFor(PublicKey key) {
        return switch (key.getAlgorithm()) {
            case "RSA" -> "1.2.840.113549.1.1.1";  // rsaEncryption (PKCS#1 v1.5)
            case "EC" -> "1.2.840.10045.2.1";      // ecPublicKey (ECDSA)
            default -> throw new IllegalArgumentException("unsupported key type " + key.getAlgorithm());
        };
    }

    /**
     * "SHA256withRSA" means: first SHA-256 over the input, then the RSA check. The hash step is
     * built in. "NONEwithRSA" (used in the tests) would skip it and expect the hash as input.
     */
    private static String javaAlgorithmFor(PublicKey key) {
        return switch (key.getAlgorithm()) {
            case "RSA" -> "SHA256withRSA";
            case "EC" -> "SHA256withECDSA";
            default -> null;
        };
    }
}
