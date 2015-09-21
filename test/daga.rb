require_relative "helper"

class User < Struct.new(:id, :auth_user_id)
  extend Daga::Model
  UUID = SecureRandom.uuid

  def self.[](id)
    User.new(1, UUID) unless id.to_s.empty?
  end

  def self.authenticate(username, password)
    User.new(1001, UUID) if username == "quentin" && password == "password"
  end
end

class Context
  def initialize(path)
    @path = path
  end

  def env
    { "SCRIPT_NAME" => "", "PATH_INFO" => @path, "HTTP_AUTHORIZATION" => "Bearer #{JWT.encode({auth: User::UUID}, Daga.secret)}" }
  end

  class Request < Struct.new(:fullpath)
  end

  def req
    Request.new(@path)
  end

  def redirect(redirect = nil)
    @redirect = redirect if redirect
    @redirect
  end

  include Daga::Helpers
end

setup do
  Context.new("/events/1")
end

class Admin < Struct.new(:id)
  def self.[](id)
    new(id) unless id.to_s.empty?
  end
end

test "login success" do |context|
  assert context.login(User, "quentin", "password")
  granted_token = context.login(User, "quentin", "password")
  assert User::UUID == Daga::AuthToken.decode(granted_token, Daga.secret)["auth"]
end

test "login failure" do |context|
  assert ! context.login(User, "wrong", "creds")
  assert nil == context.authenticated
end

test "grant_jwt_to" do |context|
  user = User[1001]
  granted_token = context.grant_jwt_to(user)
  assert user.auth_user_id  == Daga::AuthToken.decode(granted_token, Daga.secret)["auth"]
end
