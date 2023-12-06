# frozen_string_literal: true

$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), "lib"))

Gem::Specification.new do |s|
  s.name = "truelayer-signing"
  s.version = "0.2.2"
  s.summary = "Ruby gem to produce and verify TrueLayer API requests signatures"
  s.description = "TrueLayer provides instant access to open banking to " \
    "easily integrate next-generation payments and financial data into any app." \
    "This helps easily sign TrueLayer API requests using a JSON web signature."
  s.author = "Kevin Plattret"
  s.email = "kevin@truelayer.com"
  s.homepage = "https://github.com/TrueLayer/truelayer-signing/tree/main/ruby"
  s.licenses = ["Apache-2.0", "MIT"]

  s.metadata = {
    "bug_tracker_uri" => "https://github.com/TrueLayer/truelayer-signing/issues",
    "changelog_uri" => "https://github.com/TrueLayer/truelayer-signing/blob/main/ruby/CHANGELOG.md",
    "rubygems_mfa_required" => "true"
  }

  s.files = Dir[
    "CHANGELOG.md",
    "Gemfile",
    "LICENSE*",
    "README.md",
    "Rakefile",
    "lib/**/*.*",
    "test/**/*.*",
    "truelayer-signing.gemspec",
  ]
  s.require_path = "lib"

  s.required_ruby_version = ">= 2.7"
  s.add_runtime_dependency("jwt", "~> 2.7")
end
