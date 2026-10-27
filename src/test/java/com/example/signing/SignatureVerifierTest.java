package com.example.signing;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.HexFormat;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Tests the verification without the stub. We sign the way signHash does on the server: over the
 * SHA-256 hash, not over the document. "NONEwith..." signs the given bytes as they are.
 */
class SignatureVerifierTest {

    private static final byte[] DOCUMENT = "Koopakte Notarius".getBytes(StandardCharsets.UTF_8);

    @ParameterizedTest
    @ValueSource(strings = {"RSA", "EC"})
    void acceptsSignatureOverTheDocument(String keyType) throws Exception {
        KeyPair keys = keyPair(keyType);
        byte[] signature = signHashLikeTheApi(DOCUMENT, keys);

        assertTrue(SignatureVerifier.verify(DOCUMENT, signature, keys.getPublic()).valid());
    }

    @ParameterizedTest
    @ValueSource(strings = {"RSA", "EC"})
    void rejectsModifiedDocument(String keyType) throws Exception {
        KeyPair keys = keyPair(keyType);
        byte[] signature = signHashLikeTheApi(DOCUMENT, keys);
        byte[] modified = "Koopakte Notarius!".getBytes(StandardCharsets.UTF_8);

        assertFalse(SignatureVerifier.verify(modified, signature, keys.getPublic()).valid());
    }

    @ParameterizedTest
    @ValueSource(strings = {"RSA", "EC"})
    void rejectsSignatureFromAnotherKey(String keyType) throws Exception {
        byte[] signature = signHashLikeTheApi(DOCUMENT, keyPair(keyType));

        assertFalse(SignatureVerifier.verify(DOCUMENT, signature, keyPair(keyType).getPublic()).valid());
    }

    /** Pieter's mistake: passing the hash to SHA256withRSA makes Java hash it a second time. */
    @ParameterizedTest
    @ValueSource(strings = {"RSA", "EC"})
    void hashAsInputFailsEvenThoughSignatureIsFine(String keyType) throws Exception {
        KeyPair keys = keyPair(keyType);
        byte[] signature = signHashLikeTheApi(DOCUMENT, keys);

        assertFalse(SignatureVerifier.verify(sha256(DOCUMENT), signature, keys.getPublic()).valid());
    }

    private static byte[] signHashLikeTheApi(byte[] document, KeyPair keys) throws Exception {
        byte[] hash = sha256(document);
        if (keys.getPrivate().getAlgorithm().equals("RSA")) {
            // RSA PKCS#1 v1.5 signs DigestInfo = (ASN.1 header naming SHA-256) + hash
            byte[] header = HexFormat.of().parseHex("3031300d060960864801650304020105000420");
            byte[] digestInfo = new byte[header.length + hash.length];
            System.arraycopy(header, 0, digestInfo, 0, header.length);
            System.arraycopy(hash, 0, digestInfo, header.length, hash.length);
            return sign("NONEwithRSA", keys, digestInfo);
        }
        return sign("NONEwithECDSA", keys, hash);
    }

    private static byte[] sign(String algorithm, KeyPair keys, byte[] input) throws Exception {
        Signature signer = Signature.getInstance(algorithm);
        signer.initSign(keys.getPrivate());
        signer.update(input);
        return signer.sign();
    }

    private static KeyPair keyPair(String type) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(type);
        if (type.equals("EC")) {
            generator.initialize(new ECGenParameterSpec("secp256r1"));
        } else {
            generator.initialize(2048);
        }
        return generator.generateKeyPair();
    }

    private static byte[] sha256(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }
}
