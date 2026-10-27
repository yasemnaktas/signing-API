package com.example.signing;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Talks to the Signing API (CSC v1) service stub.
 *
 * The stub has no signer and no user interaction: /oauth2/authorize answers immediately with a
 * redirect that already contains the authorization code. So instead of running a local web server
 * and opening a browser, we read the code straight from the Location header. Against the real API
 * the signer has to approve in a browser/app, so this shortcut only works on the stub.
 */
public class StubClient {

    private static final String REDIRECT_URI = "http://localhost/callback";
    private static final String SHA256_OID = "2.16.840.1.101.3.4.2.1";

    private final String baseUrl;
    private final String clientId;
    private final String clientSecret;
    private final HttpClient http = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();
    private final ObjectMapper json = new ObjectMapper();

    public StubClient(String baseUrl, String clientId, String clientSecret) {
        this.baseUrl = baseUrl;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    /** Step 1: service token, used for every CSC call. */
    public String serviceToken() throws IOException, InterruptedException {
        return token(authorize(Map.of("scope", "service")));
    }

    /**
     * Step 3: the signer authorises exactly this hash. The resulting token is the SAD
     * (Signature Activation Data) that signHash requires.
     */
    public String sad(String credentialId, byte[] hash) throws IOException, InterruptedException {
        return token(authorize(Map.of(
                "scope", "credential",
                "credentialID", credentialId,
                "numSignatures", "1",
                "hash", Base64.getUrlEncoder().withoutPadding().encodeToString(hash))));
    }

    /** Step 2a: the stub client sees exactly one credential; we take the first. */
    public String firstCredentialId(String serviceToken) throws IOException, InterruptedException {
        JsonNode ids = post("/csc/v1/credentials/list", serviceToken, json.createObjectNode())
                .path("credentialIDs");
        if (ids.isEmpty()) {
            throw new IOException("credentials/list returned no credentials");
        }
        return ids.get(0).asText();
    }

    /** Step 2b: the certificate chain, signer's certificate first. */
    public List<X509Certificate> certificateChain(String serviceToken, String credentialId)
            throws IOException, InterruptedException {
        ObjectNode body = json.createObjectNode()
                .put("credentialID", credentialId)
                .put("certificates", "chain");
        JsonNode certs = post("/csc/v1/credentials/info", serviceToken, body)
                .path("cert").path("certificates");
        if (certs.isEmpty()) {
            throw new IOException("credentials/info returned no certificates");
        }
        List<X509Certificate> chain = new ArrayList<>();
        for (JsonNode cert : certs) {
            chain.add(parseCertificate(cert.asText()));
        }
        return chain;
    }

    /** Step 4: sign the hash. Returns the raw signature value (not a signed document). */
    public byte[] signHash(String serviceToken, String credentialId, String sad, byte[] hash,
                           String signAlgoOid) throws IOException, InterruptedException {
        ObjectNode body = json.createObjectNode()
                .put("credentialID", credentialId)
                .put("SAD", sad)
                .put("hashAlgo", SHA256_OID)
                .put("signAlgo", signAlgoOid);
        body.putArray("hash").add(Base64.getEncoder().encodeToString(hash));

        JsonNode signatures = post("/csc/v1/signatures/signHash", serviceToken, body)
                .path("signatures");
        if (signatures.isEmpty()) {
            throw new IOException("signHash returned no signatures");
        }
        return Base64.getDecoder().decode(signatures.get(0).asText());
    }

    // --- OAuth 2.0 authorization code flow ---

    private String authorize(Map<String, String> extraParams) throws IOException, InterruptedException {
        String state = randomState();
        Map<String, String> params = new HashMap<>(extraParams);
        params.put("response_type", "code");
        params.put("client_id", clientId);
        params.put("redirect_uri", REDIRECT_URI);
        params.put("state", state);

        HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + "/oauth2/authorize?" + formEncode(params)))
                .GET()
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());

        String location = response.headers().firstValue("Location")
                .orElseThrow(() -> new IOException("authorize did not redirect (HTTP "
                        + response.statusCode() + "): " + response.body()));
        Map<String, String> query = parseQuery(URI.create(location).getRawQuery());

        if (query.containsKey("error")) {
            throw new IOException("authorize failed: " + query.get("error")
                    + " " + query.getOrDefault("error_description", ""));
        }
        if (!state.equals(query.get("state"))) {
            throw new IOException("authorize returned a different state; possible CSRF, aborting");
        }
        String code = query.get("code");
        if (code == null) {
            throw new IOException("authorize redirect contains no code: " + location);
        }
        return code;
    }

    private String token(String code) throws IOException, InterruptedException {
        String basic = Base64.getEncoder().encodeToString(
                (clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
        String form = formEncode(Map.of(
                "grant_type", "authorization_code",
                "code", code,
                "client_id", clientId,
                "redirect_uri", REDIRECT_URI));

        HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + "/oauth2/token"))
                .header("Authorization", "Basic " + basic)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form))
                .build();
        JsonNode body = send(request);
        if (!body.hasNonNull("access_token")) {
            throw new IOException("token response contains no access_token");
        }
        return body.get("access_token").asText();
    }

    // --- HTTP helpers ---

    private JsonNode post(String path, String bearerToken, ObjectNode body)
            throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .header("Authorization", "Bearer " + bearerToken)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                .build();
        return send(request);
    }

    /** Sends a request and fails with the API's own error text, which is where the useful detail is. */
    private JsonNode send(HttpRequest request) throws IOException, InterruptedException {
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IOException(request.uri().getPath() + " failed with HTTP "
                    + response.statusCode() + ": " + response.body());
        }
        return json.readTree(response.body());
    }

    private static X509Certificate parseCertificate(String base64Der) throws IOException {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(base64Der)));
        } catch (CertificateException e) {
            throw new IOException("could not parse certificate from credentials/info", e);
        }
    }

    private static String randomState() {
        byte[] bytes = new byte[16];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String formEncode(Map<String, String> params) {
        StringBuilder sb = new StringBuilder();
        params.forEach((key, value) -> {
            if (sb.length() > 0) {
                sb.append('&');
            }
            sb.append(URLEncoder.encode(key, StandardCharsets.UTF_8))
                    .append('=')
                    .append(URLEncoder.encode(value, StandardCharsets.UTF_8));
        });
        return sb.toString();
    }

    private static Map<String, String> parseQuery(String rawQuery) {
        Map<String, String> result = new HashMap<>();
        if (rawQuery == null) {
            return result;
        }
        for (String pair : rawQuery.split("&")) {
            String[] kv = pair.split("=", 2);
            result.put(URLDecoder.decode(kv[0], StandardCharsets.UTF_8),
                    kv.length == 2 ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : "");
        }
        return result;
    }
}
