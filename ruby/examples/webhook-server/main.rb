# frozen_string_literal: true

require "http"
require "truelayer-signing"
require "webrick"

class TrueLayerSigningExamples
  # NOTE: the webhook path can be whatever is configured for your application.
  # Here a unique path is used, matching the example signature in the README.
  WEBHOOK_PATH = "/hook/d7a2c49d-110a-4ed2-a07d-8fdb3ea6424b"

  class << self
    def run_webhook_server
      server = WEBrick::HTTPServer.new(Port: 4567)

      puts "Server running at http://localhost:4567"

      server.mount_proc("/") do |req, res|
        status, body = handle_request.call(parse_request(req))
        headers = { "Content-Type" => "text/plain" }

        send_response(res, status, headers, body)
      rescue StandardError => e
        puts e
      end

      server.start
    ensure
      server.shutdown
    end

    private

    def parse_request(request)
      {
        method: request.request_method,
        path: request.path,
        headers: headers_to_hash(request.header),
        body: request.body
      }
    end

    def handle_request
      proc do |request|
        if request[:method] == "POST" && request[:path] == WEBHOOK_PATH
          verify_webhook(request[:path], request[:headers], request[:body])
        else
          %w(403 Forbidden)
        end
      end
    end

    def verify_webhook(path, headers, body)
      tl_signature = headers["tl-signature"]

      return ["400", "Bad Request – Header `Tl-Signature` missing"] unless tl_signature

      jku = TrueLayerSigning.extract_jws_header(tl_signature).jku

      return ["400", "Bad Request – Signature missing `jku`"] unless jku
      return ["401", "Unauthorized – Unpermitted `jku`"] unless valid_jku?(jku)

      jwks = HTTP.get(jku)

      return ["401", "Unauthorized – Unavailable `jwks` resource"] unless jwks.status.success?

      attempt_signature_verification!(jwks, path, headers, body, tl_signature)
    end

    def attempt_signature_verification!(jwks, path, headers, body, tl_signature)
      TrueLayerSigning.verify_with_jwks(jwks.to_s)
        .set_method(:post)
        .set_path(path)
        .set_headers(headers)
        .set_body(body)
        .verify(tl_signature)

      %w(202 Accepted)
    rescue TrueLayerSigning::Error => e
      puts e

      %w(401 Unauthorized)
    end

    def valid_jku?(jku)
      [
        "https://webhooks.truelayer.com/.well-known/jwks",
        "https://webhooks.truelayer-sandbox.com/.well-known/jwks"
      ].include?(jku)
    end

    def headers_to_hash(headers)
      headers.transform_keys { |key| key.to_s.strip.downcase }.transform_values(&:first)
    end

    def send_response(response, status, headers, body)
      response.status = status
      response.header.merge!(headers)
      response.body = body
      response
    end
  end
end

TrueLayerSigningExamples.run_webhook_server
