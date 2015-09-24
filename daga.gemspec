Gem::Specification.new do |s|
  s.name = "daga"
  s.version = "0.1.0"
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
  s.add_dependency "jwt"
  s.add_development_dependency "cutest"
  s.add_development_dependency "rack-test"
  s.add_development_dependency "cuba"
end