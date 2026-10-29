# Signing case: request and verify a signature

A small Java tool that, against the Cleverbase Signing API service stub:

1. gets a service token, finds the signer's credential and prints its certificate (subject, issuer, validity, key type);
2. hashes an input file (SHA-256), has that hash authorised (SAD) and signed via `signHash`;
3. verifies the returned signature with the certificate's public key and says **valid or not, and why**;
4. also checks that the signer's certificate was issued by the next certificate in the chain and was valid at signing time.

It works with both stub clients (RSA-2048 and ECDSA P-256).

## Run it

Requires JDK 17+. The first run downloads Maven and the dependencies.

Set the stub's test credentials (from the case email or the Service stub docs page) as environment variables. They are never stored in the repository.

```powershell
# Windows (PowerShell)
$env:CSC_CLIENT_ID = "..."
$env:CSC_CLIENT_SECRET = "..."
.\mvnw.cmd -q compile exec:java "-Dexec.args=examples/contract.txt"
```

```bash
# macOS / Linux
export CSC_CLIENT_ID=... CSC_CLIENT_SECRET=...
./mvnw -q compile exec:java -Dexec.args=examples/contract.txt
```

`CSC_BASE_URL` is optional and defaults to the stub. Replace `examples/contract.txt` with any file.

Tests (no stub or credentials needed): `./mvnw test`

Example output (RSA client):

```text
Signer's certificate (credential 6dd5f48d-...)
  Subject:  CN=TEST Willeke Liselotte De Bruijn, SURNAME=De Bruijn, GIVENNAME=Willeke Liselotte, C=NL
  Issuer:   CN=TEST Cleverbase Stub Issuing CA - NOT TRUSTED, O=Cleverbase ID B.V., C=NL
  Valid:    Mon Oct 05 11:23:32 CEST 2026  to  Sat Oct 04 11:23:32 CEST 2031
  Key:      RSA, chain of 2 certificate(s)

Signed examples\contract.txt (73 bytes), signature is 256 bytes

Verification
  Signature over your file:      VALID - signature matches this file and the signer's public key (SHA256withRSA)
  Certificate chain:             VALID - issued by CN=TEST Cleverbase Stub Issuing CA - NOT TRUSTED, ... and valid at signing time
  Same file, one byte added:     INVALID - signature does not match: the file was changed, or it was signed with another key
  Hash given as input (Pieter):  INVALID - signature does not match: the file was changed, or it was signed with another key
```

## Code

| File | What it does |
|---|---|
| `Main.java` | The flow, in the order of the case: certificate, signature, verification. Prints the results. |
| `StubClient.java` | OAuth (service token and SAD) and the CSC calls: `credentials/list`, `credentials/info`, `signatures/signHash`. |
| `SignatureVerifier.java` | `verify` (signature against file and public key) and `checkChain`. Returns a result with a reason. |
| `SignatureVerifierTest.java` | Accepts a correct signature; rejects a modified file, another key, and Pieter's input. RSA and EC. |

## Why Pieter's check fails while the signature is fine

`signHash` signs the SHA-256 hash that Pieter sends. `Signature.getInstance("SHA256withRSA")` does its own SHA-256 step: you give it the **document**, it hashes it, and checks the signature over that hash. Pieter gives it the **hash** instead, so Java computes SHA-256(SHA-256(document)) and compares the signature with a hash nobody signed. The fix is one line: `verifier.update(documentBytes)` instead of `verifier.update(hash)`. The tool shows both: the file is VALID, "hash given as input" is INVALID.

## Design choices

- **No local web server or browser for OAuth.** The stub has no signer, so `/oauth2/authorize` replies at once with a redirect containing the code. The client doesn't follow redirects; it reads the code from the `Location` header and checks `state`. This keeps the tool to one command. It is **stub-only**: with the real API the signer approves in a browser/app, so you need a real redirect handler.
- **Verify over the document with the standard JCA algorithm** (`SHA256withRSA` / `SHA256withECDSA`, chosen from the certificate's key type). No hand-built DigestInfo, and it works for both stub clients. The `signAlgo` sent to `signHash` is chosen from the key type too.
- **Results with a reason, not just a boolean**, because "valid or not, and why" is what a security officer needs to log.
- **Optional extra: chain check** (signer's certificate issued by the next one in the chain, valid at signing time). I picked this one because it is the start of the answer to Pieter's "which certificate, and how do we know it is yours?"
- **Base URL in an environment variable**, as the stub docs recommend, so the same code runs against acceptance.
- **Only the JDK and Jackson.** `java.net.http` and `java.security` are enough; fewer dependencies are easier to explain.
- **Tests don't use the stub.** They sign the hash the way the server does (`NONEwithRSA` over DigestInfo, `NONEwithECDSA` over the hash) with a generated key, so they are fast and deterministic.

## What doesn't work (yet), and what I'd do next

- The OAuth shortcut only works on the stub (see above). Next: a small local callback server for acceptance/production.
- The chain check proves consistency, **not trust**: it does not check that the root is on the EU Trusted List, revocation (OCSP/CRL), key usage or qualified-certificate statements. On the stub the CA is untrusted by design.
- "Signing time" is the local clock, not a trusted timestamp.
- One file per run and one SAD per hash; signing several files with one SAD (`numSignatures` > 1) is not built.
- The file is read into memory; fine for documents, not for very large files.
- The output is a raw signature value, not a signed PDF (see Part C below).
- With `exec:java` every failure exits Maven with code 1; the program's own codes (1 invalid, 2 error) only show when run with plain `java`.

## Part C: from a raw signature to a green checkmark in Adobe

What is missing:

- **A signature container.** The raw value has to be wrapped in a CMS/CAdES `SignedData` with the signer's certificate (chain) and signed attributes (the PDF's message digest, `signing-certificate-v2`). In PAdES the API then signs the hash of those **signed attributes**, not the hash of the file. That is an important change for Notarius' current approach.
- **Embedding in the PDF** (PAdES): a signature field and dictionary with a `ByteRange` covering everything except the signature itself.
- **A trusted chain.** Adobe shows green only if the chain ends in a root it trusts (EU Trusted List / AATL). The real Cleverbase qualified CA does; the stub CA never will.
- **Long-term validity**: a trusted timestamp (PAdES B-T), and revocation data in a DSS dictionary plus a document timestamp (B-LT / B-LTA), so it still validates after the certificate expires.

Library advice: **EU DSS (Digital Signature Service)** from the European Commission. It is Java (fits Notarius' stack), implements PAdES/CAdES at all levels, supports exactly this external-signing flow (`getDataToSign` → our `signHash` → `signDocument`), and also validates. The Cleverbase docs have a "PAdES B-B with DSS" guide. Alternatives: PDFBox + Bouncy Castle (more control, but you build the PAdES details yourself and can get them wrong), or iText (good, but AGPL/commercial licence).

## Sources and tools

- Cleverbase developer docs: The signing flow, Service stub, The hash and the signature value; the stub's Swagger UI (`/docs`).
- CSC API v1 specification (credentials/info `certificates: chain`, signHash parameters).
- Java documentation for `java.security.Signature` and `java.net.http.HttpClient`.
- I checked each stub call by hand with curl first, and checked the returned signatures independently with `openssl dgst -verify`.
- AI tools: I wrote an earlier version with ChatGPT's help, and this smaller version with Claude (Claude Code). I reviewed, ran and can explain it.
