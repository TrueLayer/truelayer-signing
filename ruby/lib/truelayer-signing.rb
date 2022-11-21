require "base64"
require "forwardable"
require "jwt"

# TODO: replace with a proper solution
require "truelayer-signing/jwt"

require "truelayer-signing/config"
require "truelayer-signing/errors"
require "truelayer-signing/utils"
require "truelayer-signing/signer"
require "truelayer-signing/verifier"

module TrueLayerSigning
  @config = Config.setup

  class << self
    extend Forwardable

    attr_reader :config

    def_delegators :@config, :certificate_id, :certificate_id=
    def_delegators :@config, :private_key, :private_key=
    def_delegator :@config, :algorithm
    def_delegator :@config, :version

    def sign_with_pem
      Signer.new
    end

    def verify_with_pem(pem)
      Verifier.new(key_type: :pem, key_value: pem)
    end

    def verify_with_jwks(jwks)
      Verifier.new(key_type: :jwks, key_value: jwks)
    end

    def extract_jws_header(signature)
      Verifier.parse_tl_signature(signature).first
    end
  end
end
