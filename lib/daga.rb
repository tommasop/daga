require "armor"
require "jwt"
# Access to external API
require "faraday"
require "oj"
require "logger"

class MakeLog
  def self.log
    if @logger.nil?
      @logger = Logger.new STDOUT
      @logger.level = Logger::DEBUG
      @logger.datetime_format = '%Y-%m-%d %H:%M:%S '
    end
    @logger
  end
end

module Daga
  class Middleware
    attr :url

    def initialize(app, url = "/login", opts = {})
      @app = app
      @opts = opts

      raise 'Secret must be provided' if opts[:secret].nil?
      @secret = opts[:secret]
      @url = url
      @model = (opts[:model] || "User").constantize 
      # The external auth option will be checked to
      # add an external api call for authentication
      # it must contain the api endpoint and the username
      # and password parameters name
      # if there are permissions you need to ad th url that gives them back
      # example:
      # external_auth: { url: "http://my.api.com/login",
      #                  username: 'my_username_attribute', 
      #                  password: 'my_password_attribute', 
      #                  acl_url: "http://my.api.com/permissions" }
      @external_auth = opts[:external_auth] 
    end

    def call(env)
      req = Rack::Request.new(env)
      # Registering the request url to put in JWT sub
      # see: https://github.com/jwt/ruby-jwt#subject-claim
      MakeLog.log.info env
      @sub = req.base_url
      MakeLog.log.info @sub
      if req.post? && req.path_info == @url
        req_body = req.body ? req.body.read : nil
        login_data = case  
                     when req_body.is_a? Hash
                      req_body
                     when req_body.is_a? String
                       Oj.load( req_body ) 
                     else
                       nil
                     end
        if login_data
          @job_id = login_data[:job_id] || 1
          login(login_data[:email], login_data[:password])
        else
          @job_id = req.params["job_id"] || 1
          login(req.params["username"], req.params["password"])
        end
      else
        @app.call(env)
      end
    end

    private
    def grant_jwt_to(user)
      MakeLog.log.info user
      if user.is_a?(Hash)
        token = AuthToken.encode(token_data(user), @secret)
        # token = AuthToken.encode({ auth: user[:id], user: user, scopes: user[:scopes] }, @secret)
      else
        token = AuthToken.encode({ auth: user.id, user: user, scopes: user.scopes }, @secret)
      end
      payload = Oj.dump({"id_token" => token})
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
      external_user =  Oj.load(Faraday.get(@external_auth[:url], {@external_auth[:username] => username, @external_auth[:password] => password}).body) 
      if external_user[:login] == true
        #permissions = Oj.load(Faraday.get(@external_auth[:acl_url]).body)
        external_user[:scopes] = Oj.dump({"all" => ["all"]}) #permissions 
        grant_jwt_to(external_user)
      else
        no_auth
      end
    end

    def no_auth
      headers = {"WWW-Authenticate" => "JWT realm=\"api\""}
      Rack::Response.new([], 401, headers).finish
    end

    def token_data(user_data)
      payload = { 
        "username": user_data[:username] || "root", 
        "job_id": @job_id, 
        "sub": @sub || "http://localhost:3000",
        "services": []
      }

      if user_data[:scopes]
        user_data[:scopes].each do | service |
          payload["services"] << {  
          "name": service[:name], 
          "version": service[:version],
          "url": service[:url], 
          "role": service[:role]
        }
        end
      else
        payload["services"] << {  
          "name": "fenice", 
          "version": "2.5",
          "url": "http://localhost:3000", 
          "role": "censore"
        }
        payload["services"] << {  
          "name": "ucad", 
          "version": "beta",
          "url": "http://localhost:3000/ucad", 
          "role": "censore"
        }
      end
      MakeLog.log.info payload
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
