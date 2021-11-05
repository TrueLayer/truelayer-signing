package truelayer.signing

import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.security.PrivateKey
import java.security.PublicKey


const val KID = "45fc75cf-5649-4134-84b3-192c2c78e990";
val privateKey = File("src/test/resources/ec512-private.pem").readBytes();
val publicKey = File("src/test/resources/ec512-public.pem").readBytes();

class UsageKt {

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

        val excpetion = assertThrows(InvalidSignatureException::class.java) { verifier.verify(tlSignature) }

        assertEquals("JWS signing/verification failed: missing required header", excpetion.message)
    }

    @Test
    fun invalidButPreAttachedBody() {
        val signature = ("eyJhbGciOiJFUzUxMiIsImtpZCI6IjQ1ZmM3NWNmLTU2ND"
                + "ktNDEzNC04NGIzLTE5MmMyYzc4ZTk5MCIsInRsX3ZlcnNpb24iOiIyIiwidGxfaGV"
                + "hZGVycyI6IiJ9.UE9TVCAvYmFyCnt9.ARLa7Q5b8k5CIhfy1qrS-IkNqCDeE-VFRD"
                + "z7Lb0fXUMOi_Ktck-R7BHDMXFDzbI5TyaxIo5TGHZV_cs0fg96dlSxAERp3UaN2oC"
                + "QHIE5gQ4m5uU3ee69XfwwU_RpEIMFypycxwq1HOf4LzTLXqP_CDT8DdyX8oTwYdUB"
                + "d2d3D17Wd9UA")

        val verifier = Verifier.from(publicKey)
            .method("post")
            .path("/foo")
            .body("{}".toByteArray())

        val exception = assertThrows(InvalidSignatureException::class.java) { verifier.verify(signature) }

        assertEquals("JWS signing/verification failed: The payload Base64URL part must be empty", exception.message)
    }

    @Test
    fun signAndVerifyNoHeaders() {
        val body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}".toByteArray()
        val path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping"
        val tlSignature = Signer.from(KID, privateKey)
            .method("POST")
            .path(path)
            .body(body)
            .sign()

        val verified = Verifier.from(publicKey)
            .method("POST")
            .path(path)
            .body(body)
            .verify(tlSignature)

        assertTrue(verified)
    }
}