package truelayer.signing;

import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static java.nio.file.Files.readAllBytes;
import static org.junit.Assert.*;

public class UsageJava {

    static String KID = "45fc75cf-5649-4134-84b3-192c2c78e990";

    @Test
    public void fullSignature() throws IOException {

        byte[] privateKey = readAllBytes(new File("src/test/resources/ec512-private.pem").toPath());
        byte[] publicKey = readAllBytes(new File("src/test/resources/ec512-public.pem").toPath());

        byte[] body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}".getBytes(StandardCharsets.UTF_8);
        String idempotencyKey = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
        String path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

        String tlSignature = Signer.from(KID, privateKey)
                .header("Idempotency-Key", idempotencyKey)
                .method("post")
                .path(path)
                .body(body)
                .sign();

        boolean verified = Verifier.from(publicKey)
                .method("POST")
                .path(path)
                .header("X-Whatever", "aoitbeh")
                .header("Idempotency-Key", idempotencyKey)
                .body(body)
                .requiredHeader("Idempotency-Key")
                .verify(tlSignature);

        assertTrue(verified);
    }

    @Test
    public void verifyBodyStaticSignature() throws IOException {
        byte[] publicKey = readAllBytes(new File("src/test/resources/ec512-public.pem").toPath());

        byte[] body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}".getBytes(StandardCharsets.UTF_8);
        String idempotencyKey = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
        String path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";
        String tlSignature =
                "eyJhbGciOiJFUzUxMiIsImtpZCI6IjQ1ZmM3NWNmLTU2NDktNDEzNC04NGIzLTE5MmMyYzc4ZTk5MCIsInRsX3ZlcnNpb24iOiIyIiwidGxfaGVhZGVycyI6IklkZW1wb3RlbmN5LUtleSJ9..AfhpFccUCUKEmotnztM28SUYgMnzPNfDhbxXUSc-NByYc1g-rxMN6HS5g5ehiN5yOwb0WnXPXjTCuZIVqRvXIJ9WAPr0P9R68ro2rsHs5HG7IrSufePXvms75f6kfaeIfYKjQTuWAAfGPAeAQ52PNQSd5AZxkiFuCMDvsrnF5r0UQsGi";

        boolean verified = Verifier.from(publicKey)
                .method("POST")
                .path(path)
                .header("X-Whatever-2", "t2345d")
                .header("Idempotency-Key", idempotencyKey)
                .body(body)
                .verify(tlSignature);

        assertTrue(verified);
    }

    @Test
    public void fullRequestSignatureMethodMismatch() throws IOException {
        byte[] privateKey = readAllBytes(new File("src/test/resources/ec512-private.pem").toPath());
        byte[] publicKey = readAllBytes(new File("src/test/resources/ec512-public.pem").toPath());

        byte[] body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}".getBytes(StandardCharsets.UTF_8);
        String idempotencyKey = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
        String path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";


        String tlSignature =
                Signer.from(KID, privateKey)
                        .header("Idempotency-Key", idempotencyKey)
                        .method("post")
                        .path(path)
                        .body(body)
                        .sign();

        boolean verified = Verifier.from(publicKey)
                .method("DELETE")
                .path(path)
                .header("X-Whatever", "aoitbeh")
                .header("Idempotency-Key", idempotencyKey)
                .body(body)
                .verify(tlSignature);

        assertFalse(verified);
    }

    @Test
    public void fullRequestSignaturePathMismatch() throws IOException {
        byte[] privateKey = readAllBytes(new File("src/test/resources/ec512-private.pem").toPath());
        byte[] publicKey = readAllBytes(new File("src/test/resources/ec512-public.pem").toPath());

        byte[] body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}".getBytes(StandardCharsets.UTF_8);
        String idempotencyKey = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
        String path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";


        String tlSignature =
                Signer.from(KID, privateKey)
                        .header("Idempotency-Key", idempotencyKey)
                        .method("post")
                        .path(path)
                        .body(body)
                        .sign();

        boolean verified = Verifier.from(publicKey)
                .method("post")
                .path("/merchant_accounts/67b5b1cf-1d0c-45d4-a2ea-61bdc044327c/sweeping")
                .header("X-Whatever", "aoitbeh")
                .header("Idempotency-Key", idempotencyKey)
                .body(body)
                .verify(tlSignature);

        assertFalse(verified);
    }

    @Test
    public void fullRequestSignatureHeaderMismatch() throws IOException {
        byte[] privateKey = readAllBytes(new File("src/test/resources/ec512-private.pem").toPath());
        byte[] publicKey = readAllBytes(new File("src/test/resources/ec512-public.pem").toPath());

        byte[] body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}".getBytes(StandardCharsets.UTF_8);
        String idempotencyKey = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
        String path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

        String tlSignature =
                Signer.from(KID, privateKey)
                        .header("Idempotency-Key", idempotencyKey)
                        .method("post")
                        .path(path)
                        .body(body)
                        .sign();

        boolean verified = Verifier.from(publicKey)
                .method("post")
                .path(path)
                .header("X-Whatever", "aoitbeh")
                .header("Idempotency-Key", "something-else")
                .body(body)
                .verify(tlSignature);

        assertFalse(verified);
    }

    @Test
    public void fullRequestSignatureBodyMismatch() throws IOException {
        byte[] privateKey = readAllBytes(new File("src/test/resources/ec512-private.pem").toPath());
        byte[] publicKey = readAllBytes(new File("src/test/resources/ec512-public.pem").toPath());

        byte[] body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}".getBytes(StandardCharsets.UTF_8);
        String idempotencyKey = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
        String path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

        String tlSignature =
                Signer.from(KID, privateKey)
                        .header("Idempotency-Key", idempotencyKey)
                        .method("post")
                        .path(path)
                        .body(body)
                        .sign();

        boolean verified = Verifier.from(publicKey)
                .method("post")
                .path(path)
                .header("X-Whatever", "aoitbeh")
                .header("Idempotency-Key", idempotencyKey)
                .body("{\"max_amount_in_minor\":1234}".getBytes(StandardCharsets.UTF_8))
                .verify(tlSignature);

        assertFalse(verified);
    }

    @Test
    public void fullRequestSignatureMissingSignatureHeader() throws IOException {
        byte[] privateKey = readAllBytes(new File("src/test/resources/ec512-private.pem").toPath());
        byte[] publicKey = readAllBytes(new File("src/test/resources/ec512-public.pem").toPath());

        byte[] body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}".getBytes(StandardCharsets.UTF_8);
        String idempotencyKey = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
        String path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

        String tlSignature =
                Signer.from(KID, privateKey)
                        .header("Idempotency-Key", idempotencyKey)
                        .method("post")
                        .path(path)
                        .body(body)
                        .sign();

        boolean verified = Verifier.from(publicKey)
                .method("post")
                .path(path)
                // missing Idempotency-Key
                .header("X-Whatever", "aoitbeh")
                .body(body)
                .verify(tlSignature);

        assertFalse(verified);
    }

    @Test
    public void flexibleHeaderCaseOrderVerify() throws IOException {
        byte[] privateKey = readAllBytes(new File("src/test/resources/ec512-private.pem").toPath());
        byte[] publicKey = readAllBytes(new File("src/test/resources/ec512-public.pem").toPath());

        byte[] body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}".getBytes(StandardCharsets.UTF_8);
        String idempotencyKey = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
        String path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

        String tlSignature =
                Signer.from(KID, privateKey)
                        .method("post")
                        .path(path)
                        .header("Idempotency-Key", idempotencyKey)
                        .header("X-Custom", "123")
                        .body(body)
                        .sign();

        boolean verified = Verifier.from(publicKey)
                .method("post")
                .path(path)
                .header("X-CUSTOM", "123") // different order & case, it's ok!
                .header("idempotency-key", idempotencyKey)  // different order & case, it's ok!
                .body(body)
                .verify(tlSignature);

        assertTrue(verified);
    }

    @Test
    public void fullRequestSignatureRequiredHeaderMissingFromSignature() throws IOException {
        byte[] privateKey = readAllBytes(new File("src/test/resources/ec512-private.pem").toPath());
        byte[] publicKey = readAllBytes(new File("src/test/resources/ec512-public.pem").toPath());

        byte[] body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}".getBytes(StandardCharsets.UTF_8);
        String idempotencyKey = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
        String path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

        String tlSignature =
                Signer.from(KID, privateKey)
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

        InvalidSignatureException invalidSignatureException = assertThrows(InvalidSignatureException.class, () -> verifier.verify(tlSignature));

        assertEquals("JWS signing/verification failed: missing required header", invalidSignatureException.getMessage());
    }

    @Test
    public void invalidButPreAttachedBody() throws IOException {
        byte[] publicKey = readAllBytes(new File("src/test/resources/ec512-public.pem").toPath());

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

        InvalidSignatureException invalidSignatureException = assertThrows(InvalidSignatureException.class, () -> verifier.verify(signature));

        assertEquals("JWS signing/verification failed: The payload Base64URL part must be empty", invalidSignatureException.getMessage());
    }
}
