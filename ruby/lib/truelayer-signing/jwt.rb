# TODO: this is a custom patch of payload-related methods, from the 'jwt' gem.
# It prevents the payload from being systematically converted to and from JSON.
# To be changed in the 'jwt' gem directly, or hard-coded in this library.
module JWT
  class Encode
    # See https://github.com/jwt/ruby-jwt/blob/main/lib/jwt/encode.rb#L53-L55
    private def encode_payload
      ::JWT::Base64.url_encode(@payload)
    end
  end

  class Decode
    # See https://github.com/jwt/ruby-jwt/blob/main/lib/jwt/decode.rb#L154-L156
    private def payload
      @payload ||= ::JWT::Base64.url_decode(@segments[1])
    rescue ::JSON::ParserError
      raise JWT::DecodeError, 'Invalid segment encoding'
    end
  end
end
