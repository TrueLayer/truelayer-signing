package truelayer.signing

import scala.util.Try

object Example extends App {
  val kid = "45fc75cf-5649-4134-84b3-192c2c78e990"

  val privateKeyPem = scala.io.Source.fromResource("ec512-private.pem").mkString
  val publicKeyPem = scala.io.Source.fromResource("ec512-public.pem").mkString

  val idempotencyKey = "idemp-2076717c-9005-4811-a321-9e0787fa0382"
  val path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping"
  val body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}".getBytes

  val sign = Try {
    Signer.from(kid, privateKeyPem)
      .header("Idempotency-Key", idempotencyKey)
      .method("post")
      .path(path)
      .body(body)
      .sign()
  }

  val verify = (tlSignature: String) => Try {
    Verifier.from(publicKeyPem)
      .method("POST")
      .path(path).header("X-Whatever", "aoitbeh")
      .header("Idempotency-Key", idempotencyKey)
      .body(body).requiredHeader("Idempotency-Key")
      .verify(tlSignature)
  }

  val program = for {
    tlSignature <- sign
    _ <- verify(tlSignature)
  } yield tlSignature

  program.fold(
    t => println(s"Failed because of: $t"),
    signature => println(s"Verification succeded for signature; $signature")
  )
}
