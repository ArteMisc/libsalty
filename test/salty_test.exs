defmodule SaltyTest do
  use ExUnit.Case
  doctest Salty

  test "auth_hmacsha256" do
    input = <<"test input">>
    key = :crypto.strong_rand_bytes(Salty.Auth.Hmacsha256.key_bytes())

    {:ok, auth} = Salty.Auth.Hmacsha256.auth(input, key)
    :ok = Salty.Auth.Hmacsha256.verify(auth, input, key)
  end
end
