package truelayer.signing

import java.io.File

fun main() {

    val kid = "45fc75cf-5649-4134-84b3-192c2c78e990"

    val privateKey = File("src/main/resources/ec512-private.pem").readText()
    val publicKey = File("src/main/resources/ec512-public.pem").readText()

    val body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}".toByteArray()
    val idempotencyKey = "idemp-2076717c-9005-4811-a321-9e0787fa0382"
    val path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping"

    val tlSignature = Result.runCatching {
        Signer.from(kid, privateKey)
            .header("Idempotency-Key", idempotencyKey)
            .method("post")
            .path(path)
            .body(body)
            .sign()
    }

    tlSignature.mapCatching { signature ->
        Verifier.from(publicKey)
            .method("POST")
            .path(path)
            .header("X-Whatever", "aoitbeh")
            .header("Idempotency-Key", idempotencyKey)
            .body(body)
            .requiredHeader("Idempotency-Key")
            .verify(signature)

        signature
    }.onSuccess { s -> println("Verification succeded for signature; $s") }
        .onFailure { t -> println("Failed because of: $t") }
}