# Reply to Pieter (Notarius)

**Subject:** Re: signHash returns invalid signatures?

Hi Pieter,

Thanks for the clear description, and good that your security officer wants every signature checked. That's exactly right. The good news: the signatures are fine, and the fix on your side is one line.

**Why the check fails.** `signHash` signs the SHA-256 hash you send. `Signature.getInstance("SHA256withRSA")` also computes a SHA-256 itself: it expects the *document* as input, not the hash. Because you pass the hash, Java hashes it a second time and compares the signature with SHA-256(SHA-256(document)), which nobody signed. So the check fails every time, whichever document you use.

**How to verify correctly.**

```java
Signature verifier = Signature.getInstance("SHA256withRSA"); // "SHA256withECDSA" for EC keys
verifier.initVerify(signerCertificate.getPublicKey());
verifier.update(documentBytes);                               // the document, not the hash
boolean valid = verifier.verify(signatureBytes);
```

Choose the algorithm from the certificate's key type. Our ECDSA P-256 credentials need `SHA256withECDSA`, and a hard-coded RSA check will break on them. I've attached a small runnable example that does the whole flow against the service stub and shows the correct check next to yours.

**Which certificate, and how do you know it's the signer's and ours?** Use the first certificate that `credentials/info` returns for the credentialID you signed with; ask for `"certificates": "chain"` to get the issuing CA too. The API returning it is not proof on its own. Check that:

- the certificate chains up to a Cleverbase qualified CA that is on the EU Trusted List;
- it was valid and not revoked (OCSP/CRL) at the time of signing;
- the subject is the person who signed.

On the service stub the CA is a test CA marked "NOT TRUSTED", so this last part only works on acceptance and production.

**Is it then a legally valid signature on the document?** Not yet. What you have is a correct signature *value* over a hash, not a signed document. To get a signature that a recipient or Adobe can validate, it has to be packaged into the document in a standard format (PAdES for PDFs), with the certificate and preferably a timestamp. Our qualified certificates and signing devices are what make the result a *qualified* electronic signature under eIDAS. Whether that meets your legal requirements is a question for your compliance officer; we can give them our qualification documentation. For the PAdES step we recommend the EU DSS library; our docs have a step-by-step guide. One thing to know in advance: with PAdES you sign the hash of the signature's signed attributes, not the hash of the PDF, so the input to `signHash` changes.

If it helps, I'm happy to do a short call this week to go through it with your team.

Kind regards,
Yasemin
Integration & Support, Cleverbase

---

## Follow-up questions for Pieter

1. What do your customers ultimately receive: PDFs they open in Adobe, or something else (XML, other files)? That decides PAdES vs. CAdES/XAdES and which library fits.
2. Which credentials will your signers use, RSA or ECDSA P-256? And is your check ready for both?
3. How long must signed documents remain verifiable (for example notarial archiving periods)? That decides whether you need long-term validation (PAdES B-LTA) from the start.
