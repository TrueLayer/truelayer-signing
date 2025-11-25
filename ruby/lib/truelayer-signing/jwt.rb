# frozen_string_literal: true

# TODO: this is a custom patch of payload-related methods, from the 'jwt' gem.
# It prevents the payload from being systematically converted to and from JSON.
# To be changed in the 'jwt' gem directly, or hard-coded in this library.
module JWT
  module_function

  class TrueLayerEncode < Encode
    private

    # See https://github.com/jwt/ruby-jwt/blob/main/lib/jwt/encode.rb#L53-L55
    def encode_payload
      ::JWT::Base64.url_encode(@payload)
    end
  end

  class TrueLayerDecode < Decode
    private

    # See https://github.com/jwt/ruby-jwt/blob/main/lib/jwt/decode.rb#L154-L156
    def payload
      @payload ||= ::JWT::Base64.url_decode(@segments[1])
    rescue ::JSON::ParserError
      raise JWT::DecodeError, "Invalid segment encoding"
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
