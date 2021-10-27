package truelayer.signing

import org.junit.Assert.*
import org.junit.Test
import java.io.File

const val KID = "45fc75cf-5649-4134-84b3-192c2c78e990";
val privateKey = File("src/test/resources/ec512-private.pem").readBytes();
val publicKey = File("src/test/resources/ec512-public.pem").readBytes();

class Usage {

    @Test
    fun fullSignature() {
        val body = """{"currency":"GBP","max_amount_in_minor":5000000}""".toByteArray()
        val idempotencyKey = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
        val path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping"

        val tlSignature =
            Signer.from(KID, privateKey)
                .header("Idempotency-Key", idempotencyKey)
                .method("post")
                .path(path)
                .body(body)
                .sign()

        val verified = Verifier.from(publicKey)
            .method("POST")
            .path(path)
            .header("X-Whatever", "aoitbeh")
            .header("Idempotency-Key", idempotencyKey)
            .body(body)
            .requiredHeader("Idempotency-Key")
            .verify(tlSignature)

        assertTrue(verified)
    }

    @Test
    fun verifyBodyStaticSignature() {
        val body = """{"currency":"GBP","max_amount_in_minor":5000000}""".toByteArray()
        val idempotencyKey = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
        val path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping"
        val tlSignature =
            "eyJhbGciOiJFUzUxMiIsImtpZCI6IjQ1ZmM3NWNmLTU2NDktNDEzNC04NGIzLTE5MmMyYzc4ZTk5MCIsInRsX3ZlcnNpb24iOiIyIiwidGxfaGVhZGVycyI6IklkZW1wb3RlbmN5LUtleSJ9..AfhpFccUCUKEmotnztM28SUYgMnzPNfDhbxXUSc-NByYc1g-rxMN6HS5g5ehiN5yOwb0WnXPXjTCuZIVqRvXIJ9WAPr0P9R68ro2rsHs5HG7IrSufePXvms75f6kfaeIfYKjQTuWAAfGPAeAQ52PNQSd5AZxkiFuCMDvsrnF5r0UQsGi"

        val verified = Verifier.from(publicKey)
            .method("POST")
            .path(path)
            .header("X-Whatever-2", "t2345d")
            .header("Idempotency-Key", idempotencyKey)
            .body(body)
            .verify(tlSignature)

        assertTrue(verified)
    }

    @Test
    fun fullRequestSignatureMethodMismatch() {
        val body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}".toByteArray()
        val idempotencyKey = "idemp-2076717c-9005-4811-a321-9e0787fa0382"
        val path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping"


        val tlSignature =
            Signer.from(KID, privateKey)
                .header("Idempotency-Key", idempotencyKey)
                .method("post")
                .path(path)
                .body(body)
                .sign()

        val verified = Verifier.from(publicKey)
            .method("DELETE")
            .path(path)
            .header("X-Whatever", "aoitbeh")
            .header("Idempotency-Key", idempotencyKey)
            .body(body)
            .verify(tlSignature)

        assertFalse(verified)
    }

    @Test
    fun fullRequestSignaturePathMismatch() {
        val body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}".toByteArray()
        val idempotencyKey = "idemp-2076717c-9005-4811-a321-9e0787fa0382"
        val path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping"


        val tlSignature =
            Signer.from(KID, privateKey)
                .header("Idempotency-Key", idempotencyKey)
                .method("post")
                .path(path)
                .body(body)
                .sign()

        val verified = Verifier.from(publicKey)
            .method("post")
            .path("/merchant_accounts/67b5b1cf-1d0c-45d4-a2ea-61bdc044327c/sweeping")
            .header("X-Whatever", "aoitbeh")
            .header("Idempotency-Key", idempotencyKey)
            .body(body)
            .verify(tlSignature)

        assertFalse(verified)
    }

    @Test
    fun fullRequestSignatureHeaderMismatch() {
        val body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}".toByteArray()
        val idempotencyKey = "idemp-2076717c-9005-4811-a321-9e0787fa0382"
        val path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping"

        val tlSignature =
            Signer.from(KID, privateKey)
                .header("Idempotency-Key", idempotencyKey)
                .method("post")
                .path(path)
                .body(body)
                .sign()

        val verified = Verifier.from(publicKey)
            .method("post")
            .path(path)
            .header("X-Whatever", "aoitbeh")
            .header("Idempotency-Key", "something-else")
            .body(body)
            .verify(tlSignature)

        assertFalse(verified)
    }

    @Test
    fun fullRequestSignatureBodyMismatch() {
        val body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}".toByteArray()
        val idempotencyKey = "idemp-2076717c-9005-4811-a321-9e0787fa0382"
        val path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping"

        val tlSignature =
            Signer.from(KID, privateKey)
                .header("Idempotency-Key", idempotencyKey)
                .method("post")
                .path(path)
                .body(body)
                .sign()

        val verified = Verifier.from(publicKey)
            .method("post")
            .path(path)
            .header("X-Whatever", "aoitbeh")
            .header("Idempotency-Key", idempotencyKey)
            .body("{\"max_amount_in_minor\":1234}".toByteArray())
            .verify(tlSignature)

        assertFalse(verified)
    }

    @Test
    fun fullRequestSignatureMissingSignatureHeader() {
        val body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}".toByteArray()
        val idempotencyKey = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
        val path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping"

        val tlSignature =
            Signer.from(KID, privateKey)
                .header("Idempotency-Key", idempotencyKey)
                .method("post")
                .path(path)
                .body(body)
                .sign()

        val verified = Verifier.from(publicKey)
            .method("post")
            .path(path)
            // missing Idempotency-Key
            .header("X-Whatever", "aoitbeh")
            .body(body)
            .verify(tlSignature)

        assertFalse(verified)
    }

    @Test
    fun flexibleHeaderCaseOrderVerify() {
        val body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}".toByteArray()
        val idempotencyKey = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
        val path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping"

        val tlSignature =
            Signer.from(KID, privateKey)
                .method("post")
                .path(path)
                .header("Idempotency-Key", idempotencyKey)
                .header("X-Custom", "123")
                .body(body)
                .sign()

        val verified = Verifier.from(publicKey)
            .method("post")
            .path(path)
            .header("X-CUSTOM", "123") // different order & case, it's ok!
            .header("idempotency-key", idempotencyKey)  // different order & case, it's ok!
            .body(body)
            .verify(tlSignature)

        assertTrue(verified)
    }

    @Test
    fun fullRequestSignatureRequiredHeaderMissingFromSignature() {
        val body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}".toByteArray()
        val idempotencyKey = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
        val path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping"

        val tlSignature =
            Signer.from(KID, privateKey)
                .header("Idempotency-Key", idempotencyKey)
                .method("post")
                .path(path)
                .body(body)
                .sign()

        val verifier = Verifier.from(publicKey)
            .method("POST")
            .path(path)
            .header("Idempotency-Key", idempotencyKey)
            // Missing from signature
            .requiredHeader("X-required")
            .body(body)

        val excpetion = assertThrows(JwsErrorException::class.java) { verifier.verify(tlSignature) }

        assertEquals("JWS signing/verification failed: missing required header", excpetion.message)
    }
}