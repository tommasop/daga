require "armor"
require "securerandom"
require "uri"
require "jwt"

module Daga
  def self.secret
    raise 'Secret must be provided in a JWT_SECRET env variable' if ENV['JWT_SECRET'].nil?
    @jwt_secret ||= ENV['JWT_SECRET']
  end

  class Middleware
    attr :url
    attr :model

    def initialize(app, url = "/login", model = User)
      @app = app
      @url = url
      @model = model
    end

    def call(env)
      req = Rack::Request.new(env)

      if req.post? && req.path_info == @url
        login(@model, req.params["username"], req.params["password"])
      else
        @app.call(env)
      end
    end

    private
    def grant_jwt_to(user)
      user.auth_user_id = SecureRandom.uuid
      token = AuthToken.encode({ auth:  user.auth_user_id }, Daga.secret)
      payload = Oj.dump(token)
      Rack::Response.new([payload], 201).finish
    end

    def login(model, username, password)
      user = model.authenticate(username, password)
      if user
        grant_jwt_to(user)
      else
        headers = {"WWW-Authenticate" => "JWT realm=\"api\""}
        Rack::Response.new([], 401, headers).finish
      end
    end
  end

  module Helpers
    #def logout
    #  token.expire!
    #  model.reauth!
    #end

    # Check incoming API request with a web token
    #def check_jwt_token
    #  if valid_header?
    #    begin
    #      token = env['HTTP_AUTHORIZATION'].split(' ')[-1]
    #      # Add a leeway of 30 secs 
    #      decoded_token = AuthToken.decode(token, Daga.secret, 30)
    #    rescue ::JWT::DecodeError
    #      nil
    #    end
    #  else
    #    nil
    #    return_jwt_header_error(env)
    #  end
    #end

    #def return_jwt_header_error
    #  if env['HTTP_AUTHORIZATION'].nil?
    #    return_error('Missing Authorization header')
    #  elsif env['HTTP_AUTHORIZATION'].split(' ').first != 'Bearer'
    #    return_error('Invalid Authorization header format')
    #  end
    #end

    #def valid_header?
    #  env['HTTP_AUTHORIZATION'] =~ /\ABearer \S*\.\S*\.\S*\z/
    #end
  end

  module Model
    def self.included(model)
      model.extend(ClassMethods)
    end

    class FetchMissing < StandardError; end

    module ClassMethods
      def authenticate(username, password)
        user = fetch(username)

        if user and is_valid_password?(user, password)
          return user
        end
      end

      def fetch(login)
        raise FetchMissing, "#{self}.fetch not implemented"
      end

      def is_valid_password?(user, password)
        Daga::Password.check(password, user.crypted_password)
      end
    end

    def password=(password)
      self.crypted_password = Daga::Password.encrypt(password.to_s)
    end
  end

  module Password
    Error = Class.new(StandardError)

    # == DOS attack fix
    #
    # Excessively long passwords (e.g. 1MB strings) would hang
    # a server.
    #
    # @see: https://www.djangoproject.com/weblog/2013/sep/15/security/
    MAX_LEN = 4096

    def self.encrypt(password, salt = generate_salt)
      digest(password, salt) + salt
    end

    def self.check(password, encrypted)
      sha512, salt = encrypted.to_s[0...128], encrypted.to_s[128..-1]

      Armor.compare(digest(password, salt), sha512)
    end

  protected
    def self.digest(password, salt)
      raise Error if password.length > MAX_LEN

      Armor.digest(password, salt)
    end

    def self.generate_salt
      Armor.hex(OpenSSL::Random.random_bytes(32))
    end
  end
    
  def self.return_error(message)
    body    = { error: message }.to_json
    headers = { 'Content-Type' => 'application/json',
                'Content-Length' => body.bytesize.to_s }

    [401, headers, [body]]
  end

  # Specific JWT exceptions
  class AccessDeniedError < StandardError; end
  class NotAuthenticatedError < StandardError; end
  class AuthenticationTimeoutError < StandardError; end
  # JWT Wrapper
  class AuthToken
    # Encode a hash in a json web token
    def self.encode(payload, jwt_secret, ttl_in_seconds = 3600*8)
      payload[:exp] = (Time.now + ttl_in_seconds).to_i
      JWT.encode(payload, jwt_secret)
    end

    # Decode a token and return the payload inside
    # If will throw an error if expired or invalid. See the docs for the JWT gem.
    def self.decode(token, jwt_secret, leeway = nil)
      decoded = JWT.decode(token, jwt_secret, leeway: leeway)
      decoded[0]
    end
  end
end
