require "armor"
require "jwt"
require "jwe"
# Access to external API
require "faraday"
require "oj"
require "loga"

# Loga initialization based on previous
# configuration if existing or rescue error
# to provide new configuration
begin 
  Loga.configuration.service_name = "DAGA"
  Loga.logger.formatter = Loga.configuration.send(:assign_formatter)
rescue Loga::ConfigurationError
  Loga.configure(
    filter_parameters: [:password],
    level: ENV["LOG_LEVEL"] || "DEBUG",
    format: :gelf,
    service_name: "DAGA",
    tags: [:uuid]
  )
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
      @encrypted = opts[:encrypt] || nil
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
      @sub = env["HTTP_ORIGIN"] 
      if req.post? && req.path_info == @url
        login_data = req.body ? Oj.load(req.body.read) : nil
        Loga.logger.debug login_data
        if login_data
          @job_id = login_data[:job_id] || 0
          login(login_data[:email], login_data[:password])
        else
          Loga.logger.debug req.params
          @job_id = req.params["job_id"] || 0
          login(req.params["email"], req.params["password"])
        end
      else
        @app.call(env)
      end
    end

    private
    def grant_jwt_to(user, orig_pwd)
      Loga.logger.debug user
      if user.is_a?(Hash)
        token = AuthToken.encode(token_data(user, orig_pwd), @secret, @encrypted)
        # token = AuthToken.encode({ auth: user[:id], user: user, scopes: user[:scopes] }, @secret)
      else
        token = AuthToken.encode({ auth: user.id, user: user, scopes: user.scopes }, @secret, @encrypted)
      end
      payload = Oj.dump({"id_token" => token})
      Rack::Response.new([payload], 201).finish
    end

    def login(username, password)
      return external_login(username, password) if @external_auth
      user = @model.authenticate(username, password)
      if user
        grant_jwt_to(user, password)
      else
        no_auth
      end
    end

    def external_login(username, password)
      external_user =  Oj.load(Faraday.get(@external_auth[:url], {@external_auth[:username] => username, @external_auth[:password] => password}).body) 
      if external_user[:login] == true
        #permissions = Oj.load(Faraday.get(@external_auth[:acl_url]).body)
        #external_user[:scopes] = Oj.dump([{"all" => ["all"]}) #permissions 
        grant_jwt_to(external_user, password)
      else
        no_auth
      end
    end

    def no_auth
      headers = {"WWW-Authenticate" => "JWT realm=\"api\""}
      Rack::Response.new([], 401, headers).finish{ Oj.dump({ error: { code: "invalid_login_credentials", message: "Invalid login credentials" } }) }
    end

    def token_data(user_data, orig_pwd)
      payload = { 
        username: user_data[:name] || "root_ucad", 
        job_id: @job_id, 
        sub: @sub || "http://localhost:30eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..deshFDOJ4vfUxwhQi4imlw.pJY-qPRrYNl3gupe2k2YoDD6MiyCwgXXBV57pRYWNtOvDRWqs2StkfBAxSC437YK_KBOeQLc6IcvHCczGgpMGDJf_kqmMDRj-k_U_aHJjLWy8shmP0g1S-txmyZYVA3zieQi8ZhB31y8aRlQ0F0c3XCEFHsiOoG_gbt5noJqvxa-1gIjONmZvSO8NaJieOUQskcSr2syGLTQ0pjsfE2viOXSFfKb3lIJ5DabRW7DgxHc9rt6zGZDmJdGNZgoispOj-11S1fKBfNrvjXw-SvgEwNNFYSpVh9Av1KJcBGPbTf_6u7byB1pJrURFaNI10HnRHdxwq_jx3_zsrEZJ4XAH_i2n5V71xEWVPv_lbxI0Nbg5S2wvX9WXHj_Fd8aOCNVO-4bFTNpcOdWbivgbFNCfkVi3dicxHa7cLPRD5mhL03-VTTrlEIm9dxArYPmcoqnt9C3h04lbYp6UTqPImqTWzMJy-Ous5BuvHhXKEGyPLUdLNKAmp4e6Zyo9cw_uDkUSdybzis_3pQ3NM0ftOzpzGif8vMuRrNt0wHg01Ubb_3sNmAzZ06i4sWT_wIqS-B4Mdz3IT3mIXtHxDvQ3eUGEcbPXdH60cErwfIc5i4ZDM2f4W5-qu-PBMOu_iY6Sw9yNH5JiLDV9Q8pD8tgq2Nsm13Bcp4zPZS91fvy_wNm880RSN8VdLzVlS4TkxI1bwi8.d0LLuztksm1HkmfHYwNkww00",
        services: []
      }

      payload.merge!({ password: Base64.decode64(orig_pwd) }) if @encrypted

      if user_data[:scopes]
        user_data[:scopes].each do | service |
          payload[:services] << {  
          name: service[:name], 
          version: service[:version],
          url: service[:url], 
          role: service[:role]
        }
        end
      else
        if @job_id != 0
          payload[:services] << {  
            id: "00001",
            name: "fenice", 
            version: "2.5",
            url: "http://localhost:3000", 
            role: "admin"
          }
          payload[:services] << {  
            id: "00002",
            name: "ucad", 
            version: "beta",
            url: "http://localhost:3000/ucad", 
            role: "writer"
          }
        else
          payload[:services] << {  
            id: "00002",
            name: "ucad", 
            version: "beta",
            url: "http://localhost:9000", 
            role: "writer"
          }
        end
      end
      payload
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
        Loga.logger.debug "---- #{user.crypted_password}, #{password}"
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
      sha256, salt = encrypted.to_s[0...128], encrypted.to_s[128..-1]

      Armor.compare(digest(password, salt), sha256)
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
    def self.encode(payload, jwt_secret, key = nil, ttl_in_seconds = 3600*8)
      payload[:exp] = (Time.now + ttl_in_seconds).to_i
      token = JWT.encode(payload, jwt_secret)
      key ? self.encrypt(token, key) : token
    end

    # Decode a token and return the payload inside
    # If will throw an error if expired or invalid. See the docs for the JWT gem.
    def self.decode(token, jwt_secret, key = nil, leeway = nil)
      token = key ? self.decrypt(token,key) : token  
      decoded = JWT.decode(token, jwt_secret, leeway: leeway)
      decoded[0]
    end
    
    def self.encrypt(token, key)
      JWE.encrypt(token, key, alg: 'dir', enc: 'A128CBC-HS256')
    end

    def self.decrypt(token, key)
      JWE.decrypt(token, key)
    end
  end
end
