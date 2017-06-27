defmodule Salty.Auth.Hmacsha256 do
  use Salty.Auth
  alias Salty.Nif, as: C

  def bytes do
    C.auth_hmacsha256_BYTES()
  end

  def keybytes do
    C.auth_hmacsha256_KEYBYTES()
  end

  def auth(data, key) do
    C.auth_hmacsha256(data, key)
  end

  def verify(mac, data, key) do
    C.auth_hmacsha256_verify(mac, data, key)
  end

  def init(key) do
    C.auth_hmacsha256_init(key)
  end

  def update(state, input) do
    C.auth_hmacsha256_update(state, input)
  end

  def final(state) do
    C.auth_hmacsha256_final(state)
  end

  def final_verify(state, expected) do
    C.auth_hmacsha256_final_verify(state, expected)
  end
end
