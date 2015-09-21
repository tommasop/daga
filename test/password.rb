require_relative "helper"

scope do
  test "encrypt" do
    encrypted = Daga::Password.encrypt("password")
    assert Daga::Password.check("password", encrypted)
  end

  test "with custom 64 character salt" do
    encrypted = Daga::Password.encrypt("password", "A" * 64)
    assert Daga::Password.check("password", encrypted)
  end

  test "DOS fix" do
    too_long = '*' * (Daga::Password::MAX_LEN + 1)

    assert_raise Daga::Password::Error do
      Daga::Password.encrypt(too_long)
    end
  end
end
