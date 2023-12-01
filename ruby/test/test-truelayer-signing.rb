require "minitest/autorun"
require "truelayer-signing"

def read_file(path)
  File.read(File.expand_path(path, File.dirname(__FILE__)))
end

CERTIFICATE_ID = "45fc75cf-5649-4134-84b3-192c2c78e990".freeze
PRIVATE_KEY = read_file("../../test-resources/ec512-private.pem").freeze
PUBLIC_KEY = read_file("../../test-resources/ec512-public.pem").freeze

TrueLayerSigning.certificate_id = CERTIFICATE_ID.freeze
TrueLayerSigning.private_key = PRIVATE_KEY.freeze

class TrueLayerSigningTest < Minitest::Test
  def test_full_request_signature_should_succeed
    body = { currency: "GBP", max_amount_in_minor: 50_000_00, name: "Foo???" }.to_json
    idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382"
    path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping"

    tl_signature = TrueLayerSigning.sign_with_pem
      .set_method(:post)
      .set_path(path)
      .add_header("Idempotency-Key", idempotency_key)
      .set_body(body)
      .sign

    result = TrueLayerSigning.verify_with_pem(PUBLIC_KEY)
      .set_method(:post)
      .set_path(path)
      .require_header("Idempotency-Key")
      .add_header("X-Whatever", "aoitbeh")
      .add_header("Idempotency-Key", idempotency_key)
      .set_body(body)
      .verify(tl_signature)

    refute(result.first.include?("\nX-Whatever: aoitbeh\n"))
    assert(result.first.include?("\nIdempotency-Key: " + idempotency_key + "\n"))
    assert(result.first
      .start_with?("POST /merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping\n"))
  end

  def test_full_request_signature_without_headers_should_succeed
    body = { currency: "GBP", max_amount_in_minor: 50_000_00 }.to_json
    path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping"

    tl_signature = TrueLayerSigning.sign_with_pem
      .set_method(:post)
      .set_path(path)
      .set_body(body)
      .sign

    result = TrueLayerSigning.verify_with_pem(PUBLIC_KEY)
      .set_method(:post)
      .set_path(path)
      .add_header("X-Whatever", "aoitbeh")
      .set_body(body)
      .verify(tl_signature)

    refute(result.first.include?("\nX-Whatever: aoitbeh\n"))
    refute(result.first.include?("\nIdempotency-Key: "))
  end

  def test_full_request_signature_without_method_should_default_to_post_and_succeed
    body = { currency: "GBP", max_amount_in_minor: 50_000_00 }.to_json
    path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping"

    tl_signature = TrueLayerSigning.sign_with_pem
      .set_path(path)
      .set_body(body)
      .sign

    result = TrueLayerSigning.verify_with_pem(PUBLIC_KEY)
      .set_path(path)
      .set_body(body)
      .verify(tl_signature)

    assert(result.first
      .start_with?("POST /merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping\n"))
  end

  def test_mismatched_signature_with_attached_valid_body_should_fail
    # Signature for `/bar` but with a valid jws-body pre-attached.
    # If we run a simple jws verify on this unchanged, it'll work!
    tl_signature = "eyJhbGciOiJFUzUxMiIsImtpZCI6IjQ1ZmM3NWNmLTU2ND" +
      "ktndeZnC04NGIzLTE5MmMyYzc4ZTk5MCIsInRsX3ZlcnNpb24iOiIyIiwidGxfaGV" +
      "hZGVycyI6IiJ9.UE9TVCAvYmFyCnt9.ARLa7Q5b8k5CIhfy1qrS-IkNqCDeE-VFRD" +
      "z7Lb0fXUMOi_Ktck-R7BHDMXFDzbI5TyaxIo5TGHZV_cs0fg96dlSxAERp3UaN2oC" +
      "QHIE5gQ4m5uU3ee69XfwwU_RpEIMFypycxwq1HOf4LzTLXqP_CDT8DdyX8oTwYdUB" +
      "d2d3D17Wd9UA"

    verifier = TrueLayerSigning.verify_with_pem(PUBLIC_KEY)
      .set_method(:post)
      .set_path("/foo")
      .set_body("{}")

    error = assert_raises(TrueLayerSigning::Error) { verifier.verify(tl_signature) }
    assert_equal("Invalid signature format", error.message)
  end

  def test_mismatched_signature_with_attached_valid_body_and_trailing_dots_should_fail
    # Signature for `/bar` but with a valid jws-body pre-attached.
    # If we run a simple jws verify on this unchanged, it'll work!
    tl_signature = "eyJhbGciOiJFUzUxMiIsImtpZCI6IjQ1ZmM3NWNmLTU2ND" +
      "ktndeZnC04NGIzLTE5MmMyYzc4ZTk5MCIsInRsX3ZlcnNpb24iOiIyIiwidGxfaGV" +
      "hZGVycyI6IiJ9.UE9TVCAvYmFyCnt9.ARLa7Q5b8k5CIhfy1qrS-IkNqCDeE-VFRD" +
      "z7Lb0fXUMOi_Ktck-R7BHDMXFDzbI5TyaxIo5TGHZV_cs0fg96dlSxAERp3UaN2oC" +
      "QHIE5gQ4m5uU3ee69XfwwU_RpEIMFypycxwq1HOf4LzTLXqP_CDT8DdyX8oTwYdUB" +
      "d2d3D17Wd9UA...."

    verifier = TrueLayerSigning.verify_with_pem(PUBLIC_KEY)
      .set_method(:post)
      .set_path("/foo")
      .set_body("{}")

    error = assert_raises(TrueLayerSigning::Error) { verifier.verify(tl_signature) }
    assert_equal("Invalid signature format", error.message)
  end

  def test_full_request_with_static_signature_should_succeed
    body = { currency: "GBP", max_amount_in_minor: 50_000_00, name: "Foo???" }.to_json
    idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382"
    path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping"
    tl_signature = read_file("../../test-resources/tl-signature.txt")

    result = TrueLayerSigning.verify_with_pem(PUBLIC_KEY)
      .set_method(:post)
      .set_path(path)
      .add_header("X-Whatever-2", "t2345d")
      .add_header("Idempotency-Key", idempotency_key)
      .set_body(body)
      .verify(tl_signature)

    refute(result.first.include?("\nX-Whatever-2: t2345d\n"))
    assert(result.first.include?("\nIdempotency-Key: " + idempotency_key + "\n"))
    assert(result.first
      .start_with?("POST /merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping\n"))
  end

  def test_full_request_with_invalid_signature_should_fail
    body = { currency: "GBP", max_amount_in_minor: 50_000_00, name: "Foo???" }.to_json
    idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382"
    path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping"
    tl_signature = "an-invalid..signature"

    verifier = TrueLayerSigning.verify_with_pem(PUBLIC_KEY)
      .set_method(:post)
      .set_path(path)
      .add_header("X-Whatever-2", "t2345d")
      .add_header("Idempotency-Key", idempotency_key)
      .set_body(body)

    error = assert_raises(TrueLayerSigning::Error) { verifier.verify(tl_signature) }
    assert_equal("Invalid base64 for header", error.message)
  end

  def test_verify_without_signed_trailing_slash_should_succeed
    body = { foo: "bar" }.to_json

    tl_signature = TrueLayerSigning.sign_with_pem
      .set_method(:post)
      .set_path("/tl-webhook/")
      .set_body(body)
      .sign

    result = TrueLayerSigning.verify_with_pem(PUBLIC_KEY)
      .set_method(:post)
      .set_path("/tl-webhook") # different
      .set_body(body)
      .verify(tl_signature)

    assert(result.first.start_with?("POST /tl-webhook/\n"))
  end

  def test_verify_with_unsigned_trailing_slash_should_succeed
    body = { foo: "bar" }.to_json

    tl_signature = TrueLayerSigning.sign_with_pem
      .set_method(:post)
      .set_path("/tl-webhook")
      .set_body(body)
      .sign

    result = TrueLayerSigning.verify_with_pem(PUBLIC_KEY)
      .set_method(:post)
      .set_path("/tl-webhook/") # different
      .set_body(body)
      .verify(tl_signature)

    assert(result.first.start_with?("POST /tl-webhook\n"))
  end

  def test_sign_an_invalid_path_should_fail
    signer = TrueLayerSigning.sign_with_pem
    error = assert_raises(TrueLayerSigning::Error) { signer.set_path("https://example.com/path") }
    assert_equal("Path must start with '/'", error.message)
  end

  def test_verify_an_invalid_path_should_fail
    verifier = TrueLayerSigning.verify_with_pem(PUBLIC_KEY)
    error = assert_raises(TrueLayerSigning::Error) { verifier.set_path("https://example.com/path") }
    assert_equal("Path must start with '/'", error.message)
  end

  def test_full_request_signature_with_method_mismatch_should_fail
    body = { currency: "GBP", max_amount_in_minor: 50_000_00 }.to_json
    idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382"
    path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping"

    tl_signature = TrueLayerSigning.sign_with_pem
      .set_method(:post)
      .set_path(path)
      .add_header("Idempotency-Key", idempotency_key)
      .set_body(body)
      .sign

    verifier = TrueLayerSigning.verify_with_pem(PUBLIC_KEY)
      .set_method(:delete) # different
      .set_path(path)
      .add_header("X-Whatever", "aoitbeh")
      .add_header("Idempotency-Key", idempotency_key)
      .set_body(body)

    error = assert_raises(TrueLayerSigning::Error) { verifier.verify(tl_signature) }
    assert_equal("Signature verification failed", error.message)
  end

  def test_full_request_signature_with_path_mismatch_should_fail
    body = { currency: "GBP", max_amount_in_minor: 50_000_00 }.to_json
    idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382"
    path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping"

    tl_signature = TrueLayerSigning.sign_with_pem
      .set_method(:post)
      .set_path(path)
      .add_header("Idempotency-Key", idempotency_key)
      .set_body(body)
      .sign

    verifier = TrueLayerSigning.verify_with_pem(PUBLIC_KEY)
      .set_method(:post)
      .set_path("/merchant_accounts/67b5b1cf-1d0c-45d4-a2ea-61bdc044327c/sweeping") # different
      .add_header("X-Whatever", "aoitbeh")
      .add_header("Idempotency-Key", idempotency_key)
      .set_body(body)

    error = assert_raises(TrueLayerSigning::Error) { verifier.verify(tl_signature) }
    assert_equal("Signature verification failed", error.message)
  end

  def test_full_request_signature_with_header_mismatch_should_fail
    body = { currency: "GBP", max_amount_in_minor: 50_000_00 }.to_json
    idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382"
    path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping"

    tl_signature = TrueLayerSigning.sign_with_pem
      .set_method(:post)
      .set_path(path)
      .add_header("Idempotency-Key", idempotency_key)
      .set_body(body)
      .sign

    verifier = TrueLayerSigning.verify_with_pem(PUBLIC_KEY)
      .set_method(:post)
      .set_path(path)
      .add_header("X-Whatever", "aoitbeh")
      .add_header("Idempotency-Key", "something-else") # different
      .set_body(body)

    error = assert_raises(TrueLayerSigning::Error) { verifier.verify(tl_signature) }
    assert_equal("Signature verification failed", error.message)
  end

  def test_full_request_signature_with_body_mismatch_should_fail
    body = { currency: "GBP", max_amount_in_minor: 50_000_00 }.to_json
    idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382"
    path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping"

    tl_signature = TrueLayerSigning.sign_with_pem
      .set_method(:post)
      .set_path(path)
      .add_header("Idempotency-Key", idempotency_key)
      .set_body(body)
      .sign

    verifier = TrueLayerSigning.verify_with_pem(PUBLIC_KEY)
      .set_method(:post)
      .set_path(path)
      .add_header("X-Whatever", "aoitbeh")
      .add_header("Idempotency-Key", idempotency_key)
      .set_body({ max_amount_in_minor: 12_34 }.to_json) # different

    error = assert_raises(TrueLayerSigning::Error) { verifier.verify(tl_signature) }
    assert_equal("Signature verification failed", error.message)
  end

  def test_full_request_signature_missing_signed_header_should_fail
    body = { currency: "GBP", max_amount_in_minor: 50_000_00 }.to_json
    idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382"
    path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping"

    tl_signature = TrueLayerSigning.sign_with_pem
      .set_method(:post)
      .set_path(path)
      .add_header("Idempotency-Key", idempotency_key)
      .set_body(body)
      .sign

    verifier = TrueLayerSigning.verify_with_pem(PUBLIC_KEY)
      .set_method(:post)
      .set_path(path)
      .add_header("X-Whatever", "aoitbeh")
      # missing 'Idempotency-Key' header
      .set_body(body)

    error = assert_raises(TrueLayerSigning::Error) { verifier.verify(tl_signature) }
    assert_equal("Missing header declared in signature: idempotency-key", error.message)
  end

  def test_full_request_signature_missing_required_header_should_fail
    body = { currency: "GBP", max_amount_in_minor: 50_000_00 }.to_json
    idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382"
    path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping"

    tl_signature = TrueLayerSigning.sign_with_pem
      .set_method(:post)
      .set_path(path)
      .add_header("Idempotency-Key", idempotency_key)
      .set_body(body)
      .sign

    verifier = TrueLayerSigning.verify_with_pem(PUBLIC_KEY)
      .set_method(:post)
      .set_path(path)
      .require_header("X-Required") # missing from signature
      .add_header("Idempotency-Key", idempotency_key)
      .set_body(body)

    error = assert_raises(TrueLayerSigning::Error) { verifier.verify(tl_signature) }
    assert_equal("Signature missing required header(s)", error.message)
  end

  def test_full_request_signature_required_header_case_insensitive_should_succeed
    body = { currency: "GBP", max_amount_in_minor: 50_000_00 }.to_json
    idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382"
    path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping"

    tl_signature = TrueLayerSigning.sign_with_pem
      .set_method(:post)
      .set_path(path)
      .add_header("Idempotency-Key", idempotency_key)
      .set_body(body)
      .sign

    result = TrueLayerSigning.verify_with_pem(PUBLIC_KEY)
      .set_method(:post)
      .set_path(path)
      .require_header("IdEmPoTeNcY-KeY") # case insensitive
      .add_header("Idempotency-Key", idempotency_key)
      .set_body(body)
      .verify(tl_signature)

    assert(result.first
      .start_with?("POST /merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping\n"))
  end

  def test_verify_with_flexible_header_case_and_order_should_succeed
    body = { currency: "GBP", max_amount_in_minor: 50_000_00 }.to_json
    idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382"
    path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping"

    tl_signature = TrueLayerSigning.sign_with_pem
      .set_method(:post)
      .set_path(path)
      .add_header("Idempotency-Key", idempotency_key)
      .add_header("X-Custom", "123")
      .set_body(body)
      .sign

    result = TrueLayerSigning.verify_with_pem(PUBLIC_KEY)
      .set_method(:post)
      .set_path(path)
      .add_header("X-CUSTOM", "123") # different case and order
      .add_header("idempotency-key", idempotency_key) # different case and order
      .set_body(body)
      .verify(tl_signature)

    assert(result.first
      .start_with?("POST /merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping\n"))
  end

  def test_extract_jws_header_should_succeed
    hook_signature = read_file("../../test-resources/webhook-signature.txt")
    jws_header = TrueLayerSigning.extract_jws_header(hook_signature)

    assert_equal("ES512", jws_header.alg)
    assert_equal(CERTIFICATE_ID, jws_header.kid)
    assert_equal("2", jws_header.tl_version)
    assert_equal("X-Tl-Webhook-Timestamp,Content-Type", jws_header.tl_headers)
    assert_equal("https://webhooks.truelayer.com/.well-known/jwks", jws_header.jku)
  end

  def test_verify_with_jwks_should_succeed
    hook_signature = read_file("../../test-resources/webhook-signature.txt")
    jwks = read_file("../../test-resources/jwks.json")
    body = { event_type: "example", event_id: "18b2842b-a57b-4887-a0a6-d3c7c36f1020" }.to_json

    TrueLayerSigning.verify_with_jwks(jwks)
      .set_method(:post)
      .set_path("/tl-webhook")
      .add_header("x-tl-webhook-timestamp", "2021-11-29T11:42:55Z")
      .add_header("content-type", "application/json")
      .set_body(body)
      .verify(hook_signature)
  end

  def test_verify_with_jwks_with_zero_padding_missing_should_succeed
    jwks = read_file("resources/missing-zero-padding-test-jwks.json")

    # JWKS with EC key missing zero padded coords is not supported by `jwt` gem

    jwks_as_json = JSON.parse(jwks, symbolize_names: true)
    jwk_missing_padding = jwks_as_json[:keys].find { |e| e[:kty] == "EC" }
    imported_jwk = JWT::JWK::EC.import(jwk_missing_padding)

    error = assert_raises(OpenSSL::PKey::EC::Point::Error) { imported_jwk.public_key.check_key }
    assert_equal("EC_POINT_bn2point: invalid encoding", error.message)

    # But supported by `truelayer-signing` using zero padding (prepend)

    payload = read_file("resources/missing-zero-padding-test-payload.json")
    body = JSON.parse(payload).to_json

    TrueLayerSigning.verify_with_jwks(jwks)
      .set_method(:post)
      .set_path("/a147f26a-f07e-47e3-9526-d52f1f1fdd55")
      .add_header("x-tl-webhook-timestamp", "2023-06-09T15:40:30Z")
      .set_body(body)
      .verify(read_file("resources/missing-zero-padding-test-signature.txt"))
  end

  def test_verify_with_jwks_with_wrong_timestamp_should_fail
    hook_signature = read_file("../../test-resources/webhook-signature.txt")
    jwks = read_file("../../test-resources/jwks.json")
    body = { event_type: "example", event_id: "18b2842b-a57b-4887-a0a6-d3c7c36f1020" }.to_json

    verifier = TrueLayerSigning.verify_with_jwks(jwks)
      .set_method(:post)
      .set_path("/tl-webhook")
      .add_header("x-tl-webhook-timestamp", "2021-12-29T11:42:55Z")
      .add_header("content-type", "application/json")
      .set_body(body)

    error = assert_raises(TrueLayerSigning::Error) { verifier.verify(hook_signature) }
    assert_equal("Signature verification failed", error.message)
  end

  # This test reproduces an issue we had with an edge case
  def test_verify_with_failed_payment_expired_webhook_should_succeed
    path = "/tl-webhook"
    payload = read_file("resources/failed-payment-expired-test-payload.json")
    body = JSON.parse(payload).to_json

    tl_signature = TrueLayerSigning.sign_with_pem
      .set_method(:post)
      .set_path(path)
      .set_body(body)
      .sign

    result = TrueLayerSigning.verify_with_pem(PUBLIC_KEY)
      .set_method(:post)
      .set_path(path)
      .set_body(body)
      .verify(tl_signature)

    assert(result.first.start_with?("POST /tl-webhook\n"))
    assert(result.first.include?("\"failure_reason\":\"expired\""))
  end

  def test_sign_with_pem_and_custom_jku_should_succeed
    body = { currency: "GBP", max_amount_in_minor: 50_000_00 }.to_json
    idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382"
    path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping"

    tl_signature_1 = TrueLayerSigning.sign_with_pem
      .set_path(path)
      .add_header("Idempotency-Key", idempotency_key)
      .set_body(body)
      .sign

    jws_header_1 = TrueLayerSigning.extract_jws_header(tl_signature_1)

    assert_nil(jws_header_1.jku)

    tl_signature_2 = TrueLayerSigning.sign_with_pem
      .set_path(path)
      .add_header("Idempotency-Key", idempotency_key)
      .set_body(body)
      .set_jku("https://webhooks.truelayer.com/.well-known/jwks")
      .sign

    jws_header_2 = TrueLayerSigning.extract_jws_header(tl_signature_2)

    assert_equal("https://webhooks.truelayer.com/.well-known/jwks", jws_header_2.jku)
  end

  # TODO: remove if/when we get rid of `lib/truelayer-signing/jwt.rb`
  def test_jwt_encode_and_decode_should_succeed
    payload_object = { currency: "GBP", max_amount_in_minor: 50_000_00 }
    token_when_object = "eyJhbGciOiJIUzI1NiJ9.eyJjdXJyZW5jeSI6IkdCUCIsIm1heF9hbW" +
      "91bnRfaW5fbWlub3IiOjUwMDAwMDB9.SjbwZCqTl6G7LQNs_M6oQhwl3a9rbqO7p3cVncLtgZY"
    token_when_json = "eyJhbGciOiJIUzI1NiJ9.IntcImN1cnJlbmN5XCI6XCJHQlBcIixcIm1h" +
      "eF9hbW91bnRfaW5fbWlub3JcIjo1MDAwMDAwfSI.rvCcgu-JevsNxbjUwJiFOuTd0hzVKvPK5RvGmaoDc7E"

    # succeeds with a hash object
    assert_equal(token_when_object, JWT.encode(payload_object, "12345", "HS256", {}))
    assert_equal(
      [{ "currency" => "GBP", "max_amount_in_minor" => 50_000_00 }, { "alg" => "HS256" }],
      JWT.decode(token_when_object, "12345", true, algorithm: "HS256")
    )

    # succeeds with a JSON string
    assert_equal(token_when_json, JWT.encode(payload_object.to_json, "12345", "HS256", {}))
    assert_equal(
      ["{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}", { "alg" => "HS256" }],
      JWT.decode(token_when_json, "12345", true, algorithm: "HS256")
    )
  end

  # TODO: remove if/when we get rid of `lib/truelayer-signing/jwt.rb`
  def test_jwt_truelayer_encode_and_decode_when_given_json_should_succeed
    payload_json = { currency: "GBP", max_amount_in_minor: 50_000_00 }.to_json
    token_when_json = "eyJhbGciOiJIUzI1NiJ9.eyJjdXJyZW5jeSI6IkdCUCIsIm1heF9hbW9" +
      "1bnRfaW5fbWlub3IiOjUwMDAwMDB9.SjbwZCqTl6G7LQNs_M6oQhwl3a9rbqO7p3cVncLtgZY"

    assert_equal(token_when_json, JWT.truelayer_encode(payload_json, "12345", "HS256", {}))
    assert_equal(
      ["{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}", { "alg" => "HS256" }],
      JWT.truelayer_decode(token_when_json, "12345", true, algorithm: "HS256")
    )
  end

  # TODO: remove if/when we get rid of `lib/truelayer-signing/jwt.rb`
  def test_jwt_truelayer_encode_when_given_a_hash_should_not_succeed
    payload_object = { currency: "GBP", max_amount_in_minor: 50_000_00 }
    error = assert_raises(TypeError) { JWT.truelayer_encode(payload_object, "12345", "HS256", {}) }
    assert_equal("no implicit conversion of Hash into String", error.message)
  end

  # TODO: remove if/when we get rid of `lib/truelayer-signing/jwt.rb`
  def test_jwt_truelayer_decode_when_given_a_hash_should_succeed
    token_when_object = "eyJhbGciOiJIUzI1NiJ9.eyJjdXJyZW5jeSI6IkdCUCIsIm1heF9hbW" +
      "91bnRfaW5fbWlub3IiOjUwMDAwMDB9.SjbwZCqTl6G7LQNs_M6oQhwl3a9rbqO7p3cVncLtgZY"

    assert_equal(
      ["{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}", { "alg" => "HS256" }],
      JWT.truelayer_decode(token_when_object, "12345", true, algorithm: "HS256")
    )
  end
end
