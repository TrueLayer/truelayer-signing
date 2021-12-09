package truelayer.signing;

import org.junit.BeforeClass;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;

import static java.nio.file.Files.readAllBytes;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

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

        byte[] body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}".getBytes(StandardCharsets.UTF_8);
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
    public void fullRequestBodyMismatch(){
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

        assertEquals("The payload Base64URL part must be empty", invalidSignatureException.getMessage());
    }

    @Test
    public void invalidButPreAttachedBodyTrailingDots() throws IOException {
        byte[] publicKey = readAllBytes(new File("src/test/resources/ec512-public.pem").toPath());

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

        assertEquals("Invalid serialized unsecured/JWS/JWE object: Too many part delimiters", invalidSignatureException.getMessage());
    }

    @Test
    public void signAndVerifyNoHeaders()  {
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

    @Test
    public void verifierExtractJku() {
        String jku = Verifier.extractJku(webhookSignature);
        assertEquals("https://webhooks.truelayer.com/.well-known/jwks", jku);
    }

    @Test
    public void verifierJwks() {
        Verifier.verifyWithJwks(jwks)
                .method("POST")
                .path("/tl-webhook")
                .header("x-tl-webhook-timestamp", "2021-11-29T11:42:55Z")
                .header("content-type", "application/json")
                .body("{\"event_type\":\"example\",\"event_id\":\"18b2842b-a57b-4887-a0a6-d3c7c36f1020\"}")
                .verify(webhookSignature); // should not throw

        Verifier verifier = Verifier.verifyWithJwks(jwks)
                .method("POST")
                .path("/tl-webhook")
                .header("x-tl-webhook-timestamp", "2021-12-02T14:18:00Z") // different
                .header("content-type", "application/json")
                .body("{\"event_type\":\"example\",\"event_id\":\"18b2842b-a57b-4887-a0a6-d3c7c36f1020\"}");

        SignatureException invalidSignatureException = assertThrows(SignatureException.class, () -> verifier.verify(webhookSignature));

        assertEquals("invalid signature", invalidSignatureException.getMessage());
    }

    private static Path testResourcePath(String subPath) {
        return Paths.get("../../test-resources/" + subPath);
    }
}
