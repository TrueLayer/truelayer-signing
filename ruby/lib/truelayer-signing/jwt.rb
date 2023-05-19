# TODO: this is a custom patch of payload-related methods, from the 'jwt' gem.
# It prevents the payload from being systematically converted to and from JSON.
# To be changed in the 'jwt' gem directly, or hard-coded in this library.
module JWT
  module_function

  class TrueLayerEncode < Encode
    # See https://github.com/jwt/ruby-jwt/blob/main/lib/jwt/encode.rb#L53-L55
    private def encode_payload
      ::JWT::Base64.url_encode(@payload)
    end
  end

  class TrueLayerDecode < Decode
    # See https://github.com/jwt/ruby-jwt/blob/main/lib/jwt/decode.rb#L154-L156
    private def payload
      @payload ||= ::JWT::Base64.url_decode(@segments[1])
    rescue ::JSON::ParserError
      raise JWT::DecodeError, 'Invalid segment encoding'
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

  def truelayer_decode(jwt, key, verify, options, &keyfinder)
    TrueLayerDecode.new(
      jwt,
      key,
      verify,
      configuration.decode.to_h.merge(options),
      &keyfinder
    ).decode_segments
  end
end
