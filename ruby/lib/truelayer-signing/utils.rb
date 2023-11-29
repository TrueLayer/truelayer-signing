# frozen_string_literal: true

module TrueLayerSigning
  class Utils
    def self.normalise_headers!(headers)
      normalised_headers = {}

      headers.to_a.each { |header| normalised_headers[header.first.downcase] = header.last }

      normalised_headers
    end
  end

  class JwsHeader
    attr_reader :alg, :kid, :tl_version, :tl_headers, :jku

    def initialize(args = {})
      raise(Error, "TRUELAYER_SIGNING_CERTIFICATE_ID is missing") \
        if TrueLayerSigning.certificate_id.nil? || TrueLayerSigning.certificate_id.empty?

      @alg = args[:alg] || TrueLayerSigning.algorithm
      @kid = args[:kid] || TrueLayerSigning.certificate_id
      @tl_version = TrueLayerSigning.version
      @tl_headers = retrieve_headers(args[:tl_headers])
      @jku = args[:jku] || nil
    end

    def to_h
      hash = instance_variables.to_h { |var| [var[1..].to_sym, instance_variable_get(var)] }

      hash.reject { |key, _value| hash[key].nil? }
    end

    def filter_headers(headers)
      required_header_keys = tl_headers.split(",").reject(&:empty?)
      normalised_headers = Utils.normalise_headers!(headers)
      ordered_headers = validate_declared_headers!(required_header_keys, normalised_headers)

      ordered_headers.to_h
    end

    private

    def validate_declared_headers!(required_header_keys, normalised_headers)
      required_header_keys.map do |key|
        value = normalised_headers[key.downcase]

        raise(Error, "Missing header declared in signature: #{key.downcase}") unless value

        [key, value]
      end
    end

    def retrieve_headers(tl_headers)
      (tl_headers.is_a?(Hash) && tl_headers.keys.join(",")) || tl_headers || ""
    end
  end

  class JwsBase
    attr_reader :method, :path, :headers, :body

    def initialize(_args = {})
      @method = "POST"
      @headers = {}
    end

    def set_method(method)
      @method = method.to_s.upcase

      self
    end

    def set_path(path)
      raise(Error, "Path must start with '/'") unless path.start_with?("/")

      @path = path

      self
    end

    def add_header(name, value)
      @headers[name.to_s] = value

      self
    end

    def set_headers(headers)
      headers.each { |name, value| @headers[name.to_s] = value }

      self
    end

    def set_body(body)
      @body = body

      self
    end

    private

    def build_signing_payload(custom_headers = nil)
      parts = []
      parts.push("#{method.upcase} #{path}")
      parts.push((custom_headers && format_headers(custom_headers)) || format_headers(headers))
      parts.push(body)
      parts.reject { |elem| elem.nil? || elem.empty? }.join("\n")
    end

    def format_headers(headers)
      headers.map { |key, value| "#{key}: #{value}" }.join("\n")
    end
  end
end
