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

# TODO: this is another patch to prevent the following error:
# OpenSSL::PKey::EC::Point::Error: EC_POINT_bn2point: invalid encoding
# See https://github.com/jwt/ruby-jwt/issues/412#issuecomment-822875854
module JWT
  module JWK
    class EC < KeyBase
      def create_ec_key(jwk_crv, jwk_x, jwk_y, jwk_d)
        curve = EC.to_openssl_curve(jwk_crv)

        x_octets = decode_octets(jwk_x)
        y_octets = decode_octets(jwk_y)

        point = OpenSSL::PKey::EC::Point.new(
          OpenSSL::PKey::EC::Group.new(curve),
          # OpenSSL::BN.new([0x04, x_octets, y_octets].pack('Ca*a*'), 2)
          OpenSSL::BN.new([0x04, x_octets, y_octets].pack(''), 2)
        )

        sequence = if jwk_d
          # https://datatracker.ietf.org/doc/html/rfc5915.html
          # ECPrivateKey ::= SEQUENCE {
          #   version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
          #   privateKey     OCTET STRING,
          #   parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
          #   publicKey  [1] BIT STRING OPTIONAL
          # }

          OpenSSL::ASN1::Sequence([
            OpenSSL::ASN1::Integer(1),
            OpenSSL::ASN1::OctetString(OpenSSL::BN.new(decode_octets(jwk_d), 2).to_s(2)),
            OpenSSL::ASN1::ObjectId(curve, 0, :EXPLICIT),
            OpenSSL::ASN1::BitString(point.to_octet_string(:uncompressed), 1, :EXPLICIT)
          ])
        else
          OpenSSL::ASN1::Sequence([
            OpenSSL::ASN1::Sequence([OpenSSL::ASN1::ObjectId('id-ecPublicKey'), OpenSSL::ASN1::ObjectId(curve)]),
            OpenSSL::ASN1::BitString(point.to_octet_string(:uncompressed))
          ])
        end

        OpenSSL::PKey::EC.new(sequence.to_der)
      end
    end
  end
end
