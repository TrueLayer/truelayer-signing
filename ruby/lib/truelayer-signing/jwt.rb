# frozen_string_literal: true

# TODO: this is a custom patch of payload-related methods, from the 'jwt' gem.
# It prevents the payload from being systematically converted to and from JSON.
# To be changed in the 'jwt' gem directly, or hard-coded in this library.
module JWT
  module_function

  class TrueLayerToken < Token
    # See https://github.com/jwt/ruby-jwt/blob/main/lib/jwt/token.rb#L61-L63
    def encoded_payload
      @encoded_payload ||= ::JWT::Base64.url_encode(payload)
    end
  end

  class TrueLayerEncode < Encode
    # See https://github.com/jwt/ruby-jwt/blob/main/lib/jwt/encode.rb#L15-L18
    def initialize(options)
      super

      @token     = TrueLayerToken.new(payload: options[:payload], header: options[:headers])
      @key       = options[:key]
      @algorithm = options[:algorithm]
    end
  end

  class TrueLayerEncodedToken < EncodedToken
    private

    # See https://github.com/jwt/ruby-jwt/blob/main/lib/jwt/encoded_token.rb#L203-L212
    def decode_payload
      raise JWT::DecodeError, "Encoded payload is empty" if encoded_payload == ""

      if unencoded_payload?
        verify_claims!(crit: ["b64"])
        return parse_unencoded(encoded_payload)
      end

      ::JWT::Base64.url_decode(encoded_payload || "")
    end
  end

  class TrueLayerDecode < Decode
    # See https://github.com/jwt/ruby-jwt/blob/main/lib/jwt/decode.rb#L22-L30
    def initialize(jwt, key, verify, options, &keyfinder)
      super

      raise JWT::DecodeError, "Nil JSON web token" unless jwt

      @token = TrueLayerEncodedToken.new(jwt)
      @key = key
      @options = options
      @verify = verify
      @keyfinder = keyfinder
    end
  end

  def truelayer_encode(payload, key, algorithm, headers)
    TrueLayerEncode.new(
      payload: payload,
      key: key,
      algorithm: algorithm,
      headers: headers
    ).segments
  end

  # rubocop:disable Style/OptionalArguments, Style/OptionalBooleanParameter, Naming/BlockForwarding
  def truelayer_decode(jwt, key, verify = true, options, &keyfinder)
    TrueLayerDecode.new(
      jwt,
      key,
      verify,
      configuration.decode.to_h.merge(options),
      &keyfinder
    ).decode_segments
  end
  # rubocop:enable Style/OptionalArguments, Style/OptionalBooleanParameter, Naming/BlockForwarding
end
