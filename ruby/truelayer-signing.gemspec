$LOAD_PATH.unshift(::File.join(::File.dirname(__FILE__), "lib"))

Gem::Specification.new do |s|
  s.name = "truelayer-signing"
  s.version = "0.1.1"
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
  }

  s.files = Dir["./**/*"]
  s.require_paths = ["lib"]

  s.required_ruby_version = ">= 2.7"
  s.add_runtime_dependency("jwt",  "2.6")
end
