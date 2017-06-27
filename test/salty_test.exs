defmodule SaltyTest do
  use ExUnit.Case
  doctest Salty

  alias Salty.Multipart, as: Multi
  alias Salty.Random, as: Rand

  test "auth" do
    prim = Salty.Auth.primitive()

    input = <<"test input">>
    {:ok, key} = Rand.buf(prim.keybytes())

    {:ok, auth} = prim.auth(input, key)
    :ok = prim.verify(auth, input, key)

    {:ok, auth_multi} = prim
                        |> Multi.init(key)
                        |> Multi.update(input)
                        |> Multi.final()

    :ok = prim
          |> Multi.init(key)
          |> Multi.update(input)
          |> Multi.final_verify(auth_multi)
  end

  test "auth_hmacsha256" do
    input = <<"test input">>

    {:ok, key} = Rand.buf(Salty.Auth.Hmacsha256.keybytes())

    {:ok, auth} = Salty.Auth.Hmacsha256.auth(input, key)
    :ok = Salty.Auth.Hmacsha256.verify(auth, input, key)

    {:ok, auth_multi} = Salty.Auth.Hmacsha256
                        |> Multi.init(key)
                        |> Multi.update(input)
                        |> Multi.final()

    :ok = Salty.Auth.Hmacsha256
          |> Multi.init(key)
          |> Multi.update(input)
          |> Multi.final_verify(auth_multi)
  end

  test "auth_hmacsha512" do
    input = <<"test input">>
    {:ok, key} = Rand.buf(Salty.Auth.Hmacsha512.keybytes())

    {:ok, auth} = Salty.Auth.Hmacsha512.auth(input, key)
    :ok = Salty.Auth.Hmacsha512.verify(auth, input, key)

    {:ok, auth_multi} = Salty.Auth.Hmacsha512
                        |> Multi.init(key)
                        |> Multi.update(input)
                        |> Multi.final()

    :ok = Salty.Auth.Hmacsha512
          |> Multi.init(key)
          |> Multi.update(input)
          |> Multi.final_verify(auth_multi)
  end

  test "auth_hmacsha512256" do
    input = <<"test input">>
    {:ok, key} = Rand.buf(Salty.Auth.Hmacsha512256.keybytes())

    {:ok, auth} = Salty.Auth.Hmacsha512256.auth(input, key)
    :ok = Salty.Auth.Hmacsha512256.verify(auth, input, key)

    {:ok, auth_multi} = Salty.Auth.Hmacsha512256
                        |> Multi.init(key)
                        |> Multi.update(input)
                        |> Multi.final()

    :ok = Salty.Auth.Hmacsha512256
          |> Multi.init(key)
          |> Multi.update(input)
          |> Multi.final_verify(auth_multi)
  end
end
