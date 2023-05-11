require 'truelayer-signing'
require 'securerandom'
require 'webrick'

class TrueLayerSigningExamples
  # Note: the webhook path can be whatever is configured for your application.
  # Here a unique path is used, matching the example signature in the README.
  WEBHOOK_PATH = "/hook/d7a2c49d-110a-4ed2-a07d-8fdb3ea6424b".freeze
  PUBLIC_KEY_PEM = <<~TXT.freeze
    -----BEGIN PUBLIC KEY-----
    MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBJ6ET9XeVCyMy+yOetZaNNCXPhwr5
    BlyDDg1CLmyNM5SvqOs8RveL6dYl4lpPur4xrPQl04ggYlVd9wnHkZnp3jcBlXw8
    Lc5phyYF1q2/QV/5wp2WHIhKDqUiXC0TvlE8d7MdTAN9yolcwrh6aWZ3kesTMZif
    BgItyT6PXUab8mMdI8k=
    -----END PUBLIC KEY-----
  TXT

  class << self
    def run_webhook_server
      ensure_certificate_id_present!

      server = WEBrick::HTTPServer.new(Port: 4567)

      puts "Server running at http://localhost:4567"

      server.mount_proc('/') do |req, res|
        request = parse_request(req)
        status, body = handle_request.call(request)
        headers = { "Content-Type" => "text/plain" }

        send_response(res, status, headers, body)
      rescue => error
        puts error
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
      Proc.new do |request|
        if request[:method] == "POST" && request[:path] == WEBHOOK_PATH
          verify_webhook(request[:path], request[:headers], request[:body])
        else
          ["403", "Forbidden"]
        end
      end
    end

    def verify_webhook(path, headers, body)
      tl_signature = headers["tl-signature"]

      return ["400", "Bad Request – Header `Tl-Signature` missing"] unless tl_signature

      begin
        TrueLayerSigning
          .verify_with_pem(PUBLIC_KEY_PEM)
          .set_method(:post)
          .set_path(path)
          .set_headers(headers)
          .set_body(body)
          .verify(tl_signature)

        ["202", "Accepted"]
      rescue TrueLayerSigning::Error
        ["401", "Unauthorized"]
      end
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

    def ensure_certificate_id_present!
      TrueLayerSigning.certificate_id || (TrueLayerSigning.certificate_id = SecureRandom.uuid)
    end
  end
end

TrueLayerSigningExamples.run_webhook_server
