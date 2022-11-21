require "http"
require "securerandom"
require "truelayer-signing"

class TrueLayerSigningExamples
  # Set required environment variables
  TRUELAYER_SIGNING_ACCESS_TOKEN = ENV.fetch("TRUELAYER_SIGNING_ACCESS_TOKEN", nil).freeze
  TRUELAYER_SIGNING_BASE_URL = "https://api.truelayer-sandbox.com".freeze

  raise(StandardError, "TRUELAYER_SIGNING_ACCESS_TOKEN is missing") \
    if TRUELAYER_SIGNING_ACCESS_TOKEN.nil? || TRUELAYER_SIGNING_ACCESS_TOKEN.empty?

  class << self
    def test_signature_endpoint
      url = "#{TRUELAYER_SIGNING_BASE_URL}/test-signature"
      idempotency_key = SecureRandom.uuid

      # A random body string is enough for this request as the `/test-signature` endpoint does not
      # require any schema, it simply checks the signature is valid against what's received.
      body = "body-#{SecureRandom.uuid}"

      # Generate a `Tl-Signature`
      signature = TrueLayerSigning.sign_with_pem
        .set_method("POST")
        .set_path("/test-signature")
        # Optional: `/test-signature` does not require any headers, but we may sign some anyway.
        # All signed headers *must* be included unmodified in the request.
        .add_header("Idempotency-Key", idempotency_key)
        .add_header("X-Bar-Header", "abc123")
        .set_body(body)
        .sign

      response = HTTP.auth("Bearer #{TRUELAYER_SIGNING_ACCESS_TOKEN}")
        .headers(idempotency_key: idempotency_key)
        .headers(x_bar_header: "abc123")
        .headers(tl_signature: signature)
        .post(url, body: body)

      return puts "✓ Signature is valid" if response.status.success?

      puts JSON.pretty_generate(JSON.parse(response.to_s))
    end
  end
end

TrueLayerSigningExamples.test_signature_endpoint
