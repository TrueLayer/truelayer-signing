module TrueLayerSigning
  class Signer < JwsBase
    attr_reader :jws_jku

    def sign
      ensure_signer_config!

      private_key = OpenSSL::PKey.read(TrueLayerSigning.private_key)
      jws_header_args = { tl_headers: headers }

      jws_header_args[:jku] = jws_jku if jws_jku

      jws_header = TrueLayerSigning::JwsHeader.new(jws_header_args).to_h
      jwt = JWT.truelayer_encode(build_signing_payload, private_key, TrueLayerSigning.algorithm,
        jws_header)
      header, _, signature = jwt.split(".")

      "#{header}..#{signature}"
    end

    def set_jku(jku)
      @jws_jku = jku

      self
    end

    private def ensure_signer_config!
      raise(Error, "TRUELAYER_SIGNING_CERTIFICATE_ID missing") \
        if TrueLayerSigning.certificate_id.nil? ||
          TrueLayerSigning.certificate_id.empty?
      raise(Error, "TRUELAYER_SIGNING_PRIVATE_KEY missing") \
        if TrueLayerSigning.private_key.nil? ||
          TrueLayerSigning.private_key.empty?
      raise(Error, "Request path missing") unless path
      raise(Error, "Request body missing") unless body
    end
  end
end
