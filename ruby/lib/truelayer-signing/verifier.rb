module TrueLayerSigning
  class Verifier < JwsBase
    attr_reader :required_headers, :key_value

    def initialize(args)
      super
      @key_value = args[:key_value]
    end

    def verify(tl_signature)
      ensure_verifier_config!

      jws_header, jws_header_b64, signature_b64 = self.class.parse_tl_signature(tl_signature)
      public_key = OpenSSL::PKey.read(key_value)

      raise(Error, "Unexpected `alg` header value") if jws_header.alg != TrueLayerSigning.algorithm

      ordered_headers = jws_header.filter_headers(headers)
      normalised_headers = {}
      ordered_headers.to_a.each { |header| normalised_headers[header.first.downcase] = header.last }

      raise(Error, "Signature missing required header(s)") if required_headers &&
        required_headers.any? { |key| !normalised_headers.has_key?(key.downcase) }

      payload_b64 = Base64.urlsafe_encode64(build_signing_payload(ordered_headers), padding: false)
      full_signature = [jws_header_b64, payload_b64, signature_b64].join(".")
      jwt_options = { algorithm: TrueLayerSigning.algorithm }

      begin
        JWT.truelayer_decode(full_signature, public_key, true, jwt_options)
      rescue JWT::VerificationError
        @path = path.end_with?("/") && path[0...-1] || path + "/"
        payload_b64 = Base64.urlsafe_encode64(build_signing_payload(ordered_headers),
                                              padding: false)
        full_signature = [jws_header_b64, payload_b64, signature_b64].join(".")

        begin
          JWT.truelayer_decode(full_signature, public_key, true, jwt_options)
        rescue
          raise(Error, "Signature verification failed")
        end
      end
    end

    def require_header(name)
      @required_headers ||= []
      @required_headers.push(name)
      self
    end

    def require_headers(names)
      @required_headers = names
      self
    end

    def self.parse_tl_signature(tl_signature)
      jws_header_b64, signature_b64 = tl_signature.split("..")

      raise(Error, "Invalid signature format") unless signature_b64

      begin
        jws_header_raw = Base64.urlsafe_decode64(jws_header_b64)
      rescue ArgumentError
        raise(Error, "Invalid base64 for header")
      else
        jws_header = JwsHeader.new(JSON.parse(jws_header_raw, symbolize_names: true))
      end

      [jws_header, jws_header_b64, signature_b64]
    end

    private def ensure_verifier_config!
      raise(Error, "Key value missing") unless key_value
    end
  end
end
