require "socket"
require "truelayer-signing"

class TrueLayerSigningExamples
  # Note: the webhook path can be whatever is configured for your application.
  # Here a unique path is used, matching the example signature in the README.
  WEBHOOK_PATH = "/hook/d7a2c49d-110a-4ed2-a07d-8fdb3ea6424b".freeze
  PUBLIC_KEY_PEM = "-----BEGIN PUBLIC KEY-----\n" +
    "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBJ6ET9XeVCyMy+yOetZaNNCXPhwr5\n" +
    "BlyDDg1CLmyNM5SvqOs8RveL6dYl4lpPur4xrPQl04ggYlVd9wnHkZnp3jcBlXw8\n" +
    "Lc5phyYF1q2/QV/5wp2WHIhKDqUiXC0TvlE8d7MdTAN9yolcwrh6aWZ3kesTMZif\n" +
    "BgItyT6PXUab8mMdI8k=\n-----END PUBLIC KEY-----"

  class << self
    def run_webhook_server
      server = TCPServer.new(4567)

      puts "Server running at http://localhost:4567"

      loop do
        Thread.start(server.accept) do |client|
          begin
            request = parse_request(client)
            status, body = handle_request.call(request)
            headers = { "Content-Type" => "text/plain" }

            send_response(client, status, headers, body)
          rescue => error
            puts error
          ensure
            client.close
          end
        end
      end
    end

    private def parse_request(client)
      request = client.gets
      headers, body = client.readpartial(2048).split("\r\n\r\n", 2)
      method, remainder = request.split(" ", 2)
      url = remainder.split(" ").first
      path, _query_strings = url.split("?", 2)

      {
        method: method,
        path: path,
        headers: headers_to_hash(headers),
        body: body
      }
    end

    private def handle_request
      Proc.new do |request|
        if request[:method] == "POST" and request[:path] == WEBHOOK_PATH
          verify_webhook(request[:path], request[:headers], request[:body])
        else
          ["403", "Forbidden"]
        end
      end
    end

    private def verify_webhook(path, headers, body)
      tl_signature = headers["tl-signature"]

      return ["400", "Bad Request – Header `Tl-Signature` missing"] unless tl_signature

      begin
        TrueLayerSigning.verify_with_pem(PUBLIC_KEY_PEM)
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

    private def send_response(client, status, headers, body)
      client.print("HTTP/1.1 #{status}\r\n")
      headers.each { |key, value| client.print("#{key}: #{value}\r\n") }
      client.print("\r\n#{body}")
    end

    private def headers_to_hash(headers_string, hash = Hash.new)
      headers_string.split("\r\n").each do |line|
        pair = line.split(":")
        hash[pair.first.to_s.strip.downcase] = pair.last.to_s.strip
      end

      hash
    end
  end
end

TrueLayerSigningExamples.run_webhook_server
