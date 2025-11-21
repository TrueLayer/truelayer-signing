package com.truelayer.signing;

import org.junit.BeforeClass;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;

import static java.nio.file.Files.readAllBytes;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class UsageTest {

    static String kid = "45fc75cf-5649-4134-84b3-192c2c78e990";

    static byte[] privateKey;
    static byte[] publicKey;
    static String webhookSignature;
    static String tlSignature;
    static String jwks;

    @BeforeClass
    public static void testData() throws IOException {
        privateKey = readAllBytes(testResourcePath("ec512-private.pem"));
        publicKey = readAllBytes(testResourcePath("ec512-public.pem"));
        webhookSignature = new String(readAllBytes(testResourcePath("webhook-signature.txt"))).trim();
        tlSignature = new String(readAllBytes(testResourcePath("tl-signature.txt")));
        jwks = new String(readAllBytes(testResourcePath("jwks.json")));
    }

    @Test
    public void fullSignature() {
        byte[] body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}".getBytes(StandardCharsets.UTF_8);
        String idempotencyKey = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
        String path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

        String tlSignature = Signer.from(kid, privateKey)
                .header("Idempotency-Key", idempotencyKey)
                .method("post")
                .path(path)
                .body(body)
                .sign();

        Verifier.from(publicKey)
                .method("POST")
                .path(path)
                .header("X-Whatever", "aoitbeh")
                .header("Idempotency-Key", idempotencyKey)
                .body(body)
                .requiredHeader("Idempotency-Key")
                .verify(tlSignature); // should not throw
    }

    @Test
    public void verifyStaticSignature() {
        byte[] body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000,\"name\":\"Foo???\"}".getBytes(StandardCharsets.UTF_8);
        String idempotencyKey = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
        String path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

        Verifier.from(publicKey)
                .method("POST")
                .path(path)
                .header("X-Whatever-2", "t2345d")
                .header("Idempotency-Key", idempotencyKey)
                .body(body)
                .verify(tlSignature); // should not throw
    }

    @Test
    public void fullRequestMethodMismatch() {
        byte[] body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}".getBytes(StandardCharsets.UTF_8);
        String idempotencyKey = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
        String path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";


        String tlSignature =
                Signer.from(kid, privateKey)
                        .header("Idempotency-Key", idempotencyKey)
                        .method("post")
                        .path(path)
                        .body(body)
                        .sign();

        Verifier verifier = Verifier.from(publicKey)
                .method("DELETE")
                .path(path)
                .header("X-Whatever", "aoitbeh")
                .header("Idempotency-Key", idempotencyKey)
                .body(body);

        SignatureException invalidSignatureException = assertThrows(SignatureException.class, () -> verifier.verify(tlSignature));

        assertEquals("invalid signature", invalidSignatureException.getMessage());
    }


    @Test
    public void fullRequestPathMismatch() {
        byte[] body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}".getBytes(StandardCharsets.UTF_8);
        String idempotencyKey = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
        String path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";


        String tlSignature =
                Signer.from(kid, privateKey)
                        .header("Idempotency-Key", idempotencyKey)
                        .method("post")
                        .path(path)
                        .body(body)
                        .sign();

        Verifier verifier = Verifier.from(publicKey)
                .method("post")
                .path("/merchant_accounts/67b5b1cf-1d0c-45d4-a2ea-61bdc044327c/sweeping")
                .header("X-Whatever", "aoitbeh")
                .header("Idempotency-Key", idempotencyKey)
                .body(body);

        SignatureException invalidSignatureException = assertThrows(SignatureException.class, () -> verifier.verify(tlSignature));

        assertEquals("invalid signature", invalidSignatureException.getMessage());
    }


    @Test
    public void fullRequestHeaderMismatch() {
        byte[] body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}".getBytes(StandardCharsets.UTF_8);
        String idempotencyKey = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
        String path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

        String tlSignature =
                Signer.from(kid, privateKey)
                        .header("Idempotency-Key", idempotencyKey)
                        .method("post")
                        .path(path)
                        .body(body)
                        .sign();

        Verifier verifier = Verifier.from(publicKey)
                .method("post")
                .path(path)
                .header("X-Whatever", "aoitbeh")
                .header("Idempotency-Key", "something-else")
                .body(body);

        SignatureException invalidSignatureException = assertThrows(SignatureException.class, () -> verifier.verify(tlSignature));

        assertEquals("invalid signature", invalidSignatureException.getMessage());
    }

    @Test
    public void fullRequestBodyMismatch() {
        byte[] body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}".getBytes(StandardCharsets.UTF_8);
        String idempotencyKey = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
        String path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

        String tlSignature =
                Signer.from(kid, privateKey)
                        .header("Idempotency-Key", idempotencyKey)
                        .method("post")
                        .path(path)
                        .body(body)
                        .sign();

        Verifier verifier = Verifier.from(publicKey)
                .method("post")
                .path(path)
                .header("X-Whatever", "aoitbeh")
                .header("Idempotency-Key", idempotencyKey)
                .body("{\"max_amount_in_minor\":1234}".getBytes(StandardCharsets.UTF_8));

        SignatureException invalidSignatureException = assertThrows(SignatureException.class, () -> verifier.verify(tlSignature));

        assertEquals("invalid signature", invalidSignatureException.getMessage());
    }

    @Test
    public void fullRequestMissingSignatureHeader() {
        byte[] body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}".getBytes(StandardCharsets.UTF_8);
        String idempotencyKey = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
        String path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

        String tlSignature =
                Signer.from(kid, privateKey)
                        .header("Idempotency-Key", idempotencyKey)
                        .method("post")
                        .path(path)
                        .body(body)
                        .sign();

        Verifier verifier = Verifier.from(publicKey)
                .method("post")
                .path(path)
                // missing Idempotency-Key
                .header("X-Whatever", "aoitbeh")
                .body(body);

        SignatureException invalidSignatureException = assertThrows(SignatureException.class, () -> verifier.verify(tlSignature));

        assertEquals("invalid signature", invalidSignatureException.getMessage());
    }

    @Test
    public void flexibleHeaderCaseOrderVerify() {
        byte[] body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}".getBytes(StandardCharsets.UTF_8);
        String idempotencyKey = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
        String path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

        String tlSignature =
                Signer.from(kid, privateKey)
                        .method("post")
                        .path(path)
                        .header("Idempotency-Key", idempotencyKey)
                        .header("X-Custom", "123")
                        .body(body)
                        .sign();

        Verifier.from(publicKey)
                .method("post")
                .path(path)
                .header("X-CUSTOM", "123") // different order & case, it's ok!
                .header("idempotency-key", idempotencyKey)  // different order & case, it's ok!
                .body(body)
                .verify(tlSignature); // should not throw
    }

    @Test
    public void fullRequestRequiredHeaderMissingFromSignature() {
        byte[] body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}".getBytes(StandardCharsets.UTF_8);
        String idempotencyKey = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
        String path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

        String tlSignature =
                Signer.from(kid, privateKey)
                        .header("Idempotency-Key", idempotencyKey)
                        .method("post")
                        .path(path)
                        .body(body)
                        .sign();

        Verifier verifier = Verifier.from(publicKey)
                .method("POST")
                .path(path)
                .header("Idempotency-Key", idempotencyKey)
                // Missing from signature
                .requiredHeader("X-required")
                .body(body);

        SignatureException invalidSignatureException = assertThrows(SignatureException.class, () -> verifier.verify(tlSignature));

        assertEquals("missing required header: X-required", invalidSignatureException.getMessage());
    }

    @Test
    public void invalidButPreAttachedBody() {
        String signature = "eyJhbGciOiJFUzUxMiIsImtpZCI6IjQ1ZmM3NWNmLTU2ND"
                + "ktNDEzNC04NGIzLTE5MmMyYzc4ZTk5MCIsInRsX3ZlcnNpb24iOiIyIiwidGxfaGV"
                + "hZGVycyI6IiJ9.UE9TVCAvYmFyCnt9.ARLa7Q5b8k5CIhfy1qrS-IkNqCDeE-VFRD"
                + "z7Lb0fXUMOi_Ktck-R7BHDMXFDzbI5TyaxIo5TGHZV_cs0fg96dlSxAERp3UaN2oC"
                + "QHIE5gQ4m5uU3ee69XfwwU_RpEIMFypycxwq1HOf4LzTLXqP_CDT8DdyX8oTwYdUB"
                + "d2d3D17Wd9UA";

        Verifier verifier = Verifier.from(publicKey)
                .method("post")
                .path("/foo")
                .body("{}".getBytes());

        SignatureException invalidSignatureException = assertThrows(SignatureException.class, () -> verifier.verify(signature));

        assertEquals("Failed to parse JWS: The payload Base64URL part must be empty", invalidSignatureException.getMessage());
    }

    @Test
    public void invalidButPreAttachedBodyTrailingDots() {
        String signature = "eyJhbGciOiJFUzUxMiIsImtpZCI6IjQ1ZmM3NWNmLTU2ND"
                + "ktNDEzNC04NGIzLTE5MmMyYzc4ZTk5MCIsInRsX3ZlcnNpb24iOiIyIiwidGxfaGV"
                + "hZGVycyI6IiJ9.UE9TVCAvYmFyCnt9.ARLa7Q5b8k5CIhfy1qrS-IkNqCDeE-VFRD"
                + "z7Lb0fXUMOi_Ktck-R7BHDMXFDzbI5TyaxIo5TGHZV_cs0fg96dlSxAERp3UaN2oC"
                + "QHIE5gQ4m5uU3ee69XfwwU_RpEIMFypycxwq1HOf4LzTLXqP_CDT8DdyX8oTwYdUB"
                + "d2d3D17Wd9UA....";

        Verifier verifier = Verifier.from(publicKey)
                .method("post")
                .path("/foo")
                .body("{}".getBytes());

        SignatureException invalidSignatureException = assertThrows(SignatureException.class, () -> verifier.verify(signature));

        assertEquals("Failed to parse JWS: Invalid serialized unsecured/JWS/JWE object: Too many part delimiters", invalidSignatureException.getMessage());
    }

    @Test
    public void signAndVerifyNoHeaders() {
        byte[] body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}".getBytes();
        String path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

        String tlSignature = Signer.from(kid, privateKey)
                .method("POST")
                .path(path)
                .body(body)
                .sign();

        Verifier.from(publicKey)
                .method("POST")
                .path(path)
                .body(body)
                .verify(tlSignature); // should not throw
    }

    // Signing a path with a single trailing slash & trying to verify
    // without that slash should still work. See #80.
    @Test
    public void signAndVerifySignedTrailingSlash() {
        byte[] body = "{\"foo\":\"bar\"}".getBytes();

        String tlSignature = Signer.from(kid, privateKey)
                .method("POST")
                .path("/tl-webhook/")
                .body(body)
                .sign();

        Verifier.from(publicKey)
                .method("POST")
                .path("/tl-webhook") // missing trailing slash
                .body(body)
                .verify(tlSignature); // should not throw
    }

    // Verify a path that matches except it has an additional trailing slash
    // should still work. See #80.
    @Test
    public void signAndVerifyUnsignedTrailingSlash() {
        byte[] body = "{\"foo\":\"bar\"}".getBytes();

        String tlSignature = Signer.from(kid, privateKey)
                .method("POST")
                .path("/tl-webhook")
                .body(body)
                .sign();

        Verifier.from(publicKey)
                .method("POST")
                .path("/tl-webhook/") // additional trailing slash
                .body(body)
                .verify(tlSignature); // should not throw
    }

    // Verify a path that matches except it has an additional trailing slash
    // should still work. See #80.
    @Test
    public void verifyJwksUnsignedTrailingSlash() {
        Verifier.verifyWithJwks(jwks)
                .method("POST")
                .path("/tl-webhook/")
                .headers(new HashMap<String, String>() {{
                    put("x-tl-webhook-timestamp", "2021-11-29T11:42:55Z");
                    put("content-type", "application/json");
                }})
                .body("{\"event_type\":\"example\",\"event_id\":\"18b2842b-a57b-4887-a0a6-d3c7c36f1020\"}")
                .verify(webhookSignature); // should not throw
    }

    @Test
    public void verifierExtractJku() {
        String jku = Verifier.extractJku(webhookSignature);
        assertEquals("https://webhooks.truelayer.com/.well-known/jwks", jku);
    }

    @Test
    public void verifierExtractJku_InvalidSignature_ThrowsSignatureException() {
        Exception e = assertThrows(
                SignatureException.class,
                () -> Verifier.extractJku("an-invalid..signature")
        );
        String actual = e.getMessage();
        // Debug: Let's see what we actually get
        if (!actual.contains("path $[")) {
            System.out.println("Actual message: " + actual);
            System.out.println("Actual message (escaped): " + actual.replace("\n", "\\n").replace("\r", "\\r"));
        }
        // The error message format changed in nimbus-jose-jwt 9.40
        // Check for key parts rather than exact match due to potential formatting differences
        assertTrue("Should contain 'Failed to parse JWS: Invalid JWS header'", 
                actual.contains("Failed to parse JWS: Invalid JWS header"));
        assertTrue("Should contain 'Expected BEGIN_OBJECT but was STRING'", 
                actual.contains("Expected BEGIN_OBJECT but was STRING"));
        assertTrue("Should contain 'path $['", 
                actual.contains("path $["));
        assertTrue("Should contain Gson troubleshooting link", 
                actual.contains("See https://github.com/google/gson/blob/main/Troubleshooting.md#unexpected-json-structure]"));
    }

    @Test
    public void verifierJwks() {
        Verifier.verifyWithJwks(jwks)
                .method("POST")
                .path("/tl-webhook")
                .headers(new HashMap<String, String>() {{
                    put("x-tl-webhook-timestamp", "2021-11-29T11:42:55Z");
                    put("content-type", "application/json");
                }})
                .body("{\"event_type\":\"example\",\"event_id\":\"18b2842b-a57b-4887-a0a6-d3c7c36f1020\"}")
                .verify(webhookSignature); // should not throw

        Verifier verifier = Verifier.verifyWithJwks(jwks)
                .method("POST")
                .path("/tl-webhook")
                .headers(new HashMap<String, String>() {{
                    put("x-tl-webhook-timestamp", "2021-12-02T14:18:00Z"); // different
                    put("content-type", "application/json");
                }})
                .body("{\"event_type\":\"example\",\"event_id\":\"18b2842b-a57b-4887-a0a6-d3c7c36f1020\"}");

        SignatureException invalidSignatureException = assertThrows(SignatureException.class, () -> verifier.verify(webhookSignature));

        assertEquals("invalid signature", invalidSignatureException.getMessage());
    }

    @Test
    public void verifierVerify_InvalidSignature_ThrowsSignatureException() {
        Exception e = assertThrows(
                SignatureException.class,
                () -> Verifier.verifyWithJwks(jwks)
                        .method("POST")
                        .path("/bar")
                        .body("{}")
                        .verify("an-invalid..signature")
        );
        String actual = e.getMessage();
        // Debug: Let's see what we actually get
        if (!actual.contains("path $[")) {
            System.out.println("Actual message: " + actual);
            System.out.println("Actual message (escaped): " + actual.replace("\n", "\\n").replace("\r", "\\r"));
        }
        // The error message format changed in nimbus-jose-jwt 9.40
        // Check for key parts rather than exact match due to potential formatting differences
        assertTrue("Should contain 'Failed to parse JWS: Invalid JSON'", 
                actual.contains("Failed to parse JWS: Invalid JSON"));
        assertTrue("Should contain 'Expected BEGIN_OBJECT but was STRING'", 
                actual.contains("Expected BEGIN_OBJECT but was STRING"));
        assertTrue("Should contain 'path $['", 
                actual.contains("path $["));
        assertTrue("Should contain Gson troubleshooting link", 
                actual.contains("See https://github.com/google/gson/blob/main/Troubleshooting.md#unexpected-json-structure]"));
    }

    @Test
    public void signInvalidPath() {
        IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class, () ->
                Signer.from(kid, privateKey)
                        .path("https://example.com/the-path") //invalid path
        );

        assertEquals("invalid path https://example.com/the-path must start with '/'", illegalArgumentException.getMessage());
    }

    @Test
    public void verifyInvalidPath() {
        IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class, () ->
                Verifier.from(publicKey)
                        .path("https://example.com/the-path") //invalid path
        );

        assertEquals("invalid path https://example.com/the-path must start with '/'", illegalArgumentException.getMessage());
    }

    private static Path testResourcePath(String subPath) {
        return Paths.get("../../test-resources/" + subPath);
    }
}
