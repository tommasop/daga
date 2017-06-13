Gem::Specification.new do |s|
  s.name = "daga"
  s.version = "0.2.0"
  s.summary = %{Generic authentication protocol for rack API/JWT applications.}
  s.description = %Q{
    Provides all the protocol you need in order to do authentication on
    your rack API/JWT application.
  }
  s.authors = ["Tommaso Patrizi"]
  s.email = ["tommasop@thinkingco.de"]
  s.homepage = "http://github.com/tommasop/daga"
  s.license = "MIT"

  s.files = `git ls-files`.split("\n")

  s.add_dependency "armor"
  s.add_dependency "jwt", "~> 1.5", ">= 1.5.6"
  # s.add_dependency "jwe", "~> 0.1.1"
  s.add_dependency "oj"
  s.add_dependency "faraday"
  s.add_dependency "loga"
  s.add_development_dependency "cutest"
  s.add_development_dependency "rack-test"
  s.add_development_dependency "cuba"
end
