defmodule SaltyTest do
  use ExUnit.Case
  doctest Salty

  alias Salty.Multipart, as: Multi
  alias Salty.Random, as: Rand

  test "auth_hmacsha256" do
    input = <<"test input">>
    {:ok, key} = Rand.buf(Salty.Auth.Hmacsha256.key_bytes())

    {:ok, auth} = Salty.Auth.Hmacsha256.auth(input, key)
    :ok = Salty.Auth.Hmacsha256.verify(auth, input, key)

    {:ok, auth_multi} =
      Multi.init(Salty.Auth.Hmacsha256, key)
      |> Multi.update(input)
      |> Multi.final()

    :ok =
      Multi.init(Salty.Auth.Hmacsha256, key)
      |> Multi.update(input)
      |> Multi.final_verify(auth_multi)
  end
end
