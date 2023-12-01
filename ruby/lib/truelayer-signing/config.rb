module TrueLayerSigning
  class Config
    attr_accessor :certificate_id, :private_key
    attr_reader :algorithm, :version

    # @return [TrueLayerSigning::Config]
    def self.setup
      new.tap do |instance|
        yield(instance) if block_given?
      end
    end

    # @return [TrueLayerSigning::Config]
    def initialize
      @algorithm = "ES512".freeze
      @certificate_id = ENV.fetch("TRUELAYER_SIGNING_CERTIFICATE_ID", nil).freeze
      @private_key = ENV.fetch("TRUELAYER_SIGNING_PRIVATE_KEY", nil)&.gsub(/\\n/, "\n").freeze
      @version = "2".freeze
    end
  end
end
