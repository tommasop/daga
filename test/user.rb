class User
  include Daga::Model

  def self.[](id)
    User.new(1001) unless id.to_s.empty?
  end

  def self.fetch(username)
    User.new(1001) if username == "quentin"
  end

  attr :id
  attr :auth_user_id, true

  def initialize(id)
    @id = id
  end

  def crypted_password
    @crypted_password ||= Daga::Password.encrypt("password")
  end
end
