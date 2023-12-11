# frozen_string_literal: true

require "http"
require "securerandom"
require "truelayer-signing"

class TrueLayerSigningExamples
  # Set required environment variables
  TRUELAYER_SIGNING_ACCESS_TOKEN = ENV.fetch("TRUELAYER_SIGNING_ACCESS_TOKEN", nil)
  TRUELAYER_SIGNING_BASE_URL = "https://api.truelayer-sandbox.com"

  raise(StandardError, "TRUELAYER_SIGNING_ACCESS_TOKEN is missing") \
    if TRUELAYER_SIGNING_ACCESS_TOKEN.nil? || TRUELAYER_SIGNING_ACCESS_TOKEN.empty?

  class << self
    def test_signature_endpoint
      path = "/test-signature"
      url = [TRUELAYER_SIGNING_BASE_URL, path].join
      idempotency_key = SecureRandom.uuid
      # A random body string is enough for this request as the `/test-signature` endpoint does not
      # require any schema, it simply checks the signature is valid against what's received.
      body = "body-#{SecureRandom.uuid}"
      signature = generate_signature!(path, idempotency_key, body)
      response = generate_response!(idempotency_key, signature, url, body)

      return puts "✓ Signature is valid" if response.status.success?

      puts JSON.pretty_generate(JSON.parse(response.to_s))
    end

    private

    def generate_response!(idempotency_key, signature, url, body)
      HTTP.auth("Bearer #{TRUELAYER_SIGNING_ACCESS_TOKEN}")
        .headers(idempotency_key: idempotency_key)
        .headers(x_bar_header: "abc123")
        .headers(tl_signature: signature)
        .post(url, body: body)
    end

    def generate_signature!(path, idempotency_key, body)
      TrueLayerSigning.sign_with_pem
        .set_method("POST")
        .set_path(path)
        # Optional: `/test-signature` does not require any headers, but we may sign some anyway.
        # All signed headers *must* be included unmodified in the request.
        .add_header("Idempotency-Key", idempotency_key)
        .add_header("X-Bar-Header", "abc123")
        .set_body(body)
        .sign
    end
  end
end

TrueLayerSigningExamples.test_signature_endpoint
