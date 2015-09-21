require_relative "helper"

class User < Struct.new(:crypted_password, :auth_user_id)
  include Daga::Model
end

test "grant_jwt" do
  user = User.new
  token = user.grant_jwt
  assert user.auth_user_id == Daga::AuthToken.decode(token, Daga.secret)['auth']
end

test "fetch" do
  ex = nil

  begin
    User.fetch("quentin")
  rescue Exception => ex
  end

  assert ex.kind_of?(Daga::Model::FetchMissing)
  assert "User.fetch not implemented" == ex.message
end

test "is_valid_password?" do
  user = User.new(Daga::Password.encrypt("password"))

  assert User.is_valid_password?(user, "password")
  assert ! User.is_valid_password?(user, "password1")
end

class User
  class << self
    attr_accessor :fetched
  end

  def self.fetch(username)
    return fetched if username == "quentin"
  end
end

test "authenticate" do
  user = User.new(Daga::Password.encrypt("pass"))

  User.fetched = user

  assert user == User.authenticate("quentin", "pass")
  assert nil == User.authenticate("unknown", "pass")
  assert nil == User.authenticate("quentin", "wrongpass")
end

test "#password=" do
  u = User.new
  u.password = "pass1234"

  assert Daga::Password.check("pass1234", u.crypted_password)
end

