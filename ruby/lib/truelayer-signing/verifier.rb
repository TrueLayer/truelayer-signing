module TrueLayerSigning
  class Verifier < JwsBase
    EXPECTED_COORDS_LENGTH = 66.freeze

    attr_reader :required_headers, :key_type, :key_value

    def initialize(args)
      super
      @key_type = args[:key_type]
      @key_value = args[:key_value]
    end

    def verify(tl_signature)
      ensure_verifier_config!

      jws_header, jws_header_b64, signature_b64 = self.class.parse_tl_signature(tl_signature)

      raise(Error, "Unexpected `alg` header value") if jws_header.alg != TrueLayerSigning.algorithm

      ordered_headers = jws_header.filter_headers(headers)
      normalised_headers = {}
      ordered_headers.to_a.each { |header| normalised_headers[header.first.downcase] = header.last }

      raise(Error, "Signature missing required header(s)") if required_headers &&
        required_headers.any? { |key| !normalised_headers.has_key?(key.downcase) }

      verify_signature_flex(ordered_headers, jws_header, jws_header_b64, signature_b64)
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

    private def verify_signature_flex(ordered_headers, jws_header, jws_header_b64, signature_b64)
      full_signature = build_full_signature(ordered_headers, jws_header_b64, signature_b64)

      begin
        verify_signature(jws_header, full_signature)
      rescue JWT::VerificationError
        @path = path.end_with?("/") && path[0...-1] || path + "/"
        full_signature = build_full_signature(ordered_headers, jws_header_b64, signature_b64)

        begin
          verify_signature(jws_header, full_signature)
        rescue JWT::VerificationError
          raise(Error, "Signature verification failed")
        end
      end
    end

    private def build_full_signature(ordered_headers, jws_header_b64, signature_b64)
      payload_b64 = Base64.urlsafe_encode64(build_signing_payload(ordered_headers), padding: false)

      [jws_header_b64, payload_b64, signature_b64].join(".")
    end

    private def verify_signature(jws_header, full_signature)
      case key_type
      when :pem
        public_key = OpenSSL::PKey.read(key_value)
      when :jwks
        public_key = retrieve_public_key(:jwks, key_value, jws_header)
      end

      jwt_options = { algorithm: TrueLayerSigning.algorithm }
      JWT.truelayer_decode(full_signature, public_key, true, jwt_options)
    end

    private def retrieve_public_key(key_type, key_value, jws_header)
      case key_type
      when :pem
        OpenSSL::PKey.read(key_value)
      when :jwks
        jwks_hash = JSON.parse(key_value, symbolize_names: true)
        jwk = jwks_hash[:keys].find { |key| key[:kid] == jws_header.kid }

        raise(Error, "JWKS does not include given `kid` value") unless jwk

        valid_jwk = apply_zero_padding_as_needed(jwk)

        JWT::JWK::EC.import(valid_jwk).public_key
      else
        raise(Error, "Type of public key not recognised")
      end
    end

    private def apply_zero_padding_as_needed(jwk)
      valid_jwk = jwk.clone

      %i(x y).each do |elem|
        coords = Base64.urlsafe_decode64(valid_jwk[elem])
        length = coords.length
        diff = EXPECTED_COORDS_LENGTH - length

        valid_jwk[elem] = Base64.urlsafe_encode64(("\x00" * diff) + coords) if diff > 0
      end

      valid_jwk
    end

    private def ensure_verifier_config!
      raise(Error, "Key value missing") unless key_value
    end
  end
end
