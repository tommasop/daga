require "armor"
require "securerandom"
require "jwt"
# Access to external API
require "faraday"

module Daga
  class Middleware
    attr :url

    def initialize(app, url = "/login", opts = {})
      @app = app
      @opts = opts

      raise 'Secret must be provided' if opts[:secret].nil?
      @secret = opts[:secret]
      @url = url
      @model = User 
      # The external auth option will be checked to
      # add an external api call for authentication
      # it must contain the api endpoint and the username
      # and password parameters name
      #
      # example:
      # external_auth: { url: "http://my.api.com/login", username: 'my_username_attribute', password: 'my_password_attribute'}
      @external_auth = opts[:external_auth] 
    end

    def call(env)
      req = Rack::Request.new(env)

      if req.post? && req.path_info == @url
        login_data = Oj.load( req.body.read )
        if login_data
          login(login_data["email"], login_data["password"])
        else
          login(req.params["username"], req.params["password"])
        end
      else
        @app.call(env)
      end
    end

    private
    def grant_jwt_to(user)
      user.auth_user_id = SecureRandom.uuid
      user.save
      token = AuthToken.encode({ auth: user.auth_user_id, scopes: user.scopes }, @secret)
      payload = Oj.dump(token)
      Rack::Response.new([payload], 201).finish
    end

    def login(username, password)
      return external_login(username, password) if @external_auth
      user = @model.authenticate(username, password)
      if user
        grant_jwt_to(user)
      else
        no_auth
      end
    end

    def external_login(username, password)
      external_user =  Faraday.post @external_auth[:url], {@external_auth[:username] => username, @external_auth[:password] => password} 
      if external_user
        permissions = Faraday.get @external_auth[:acl_url]
        external_user[:scopes] = parmissions 
        grant_jwt_to(external_user)
      else
        no_auth
      end
    end

    def no_auth
      headers = {"WWW-Authenticate" => "JWT realm=\"api\""}
      Rack::Response.new([], 401, headers).finish
    end
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
