defmodule Salty.Auth.Hmacsha512 do
  use Salty.Auth

  def bytes do
    C.auth_hmacsha512_BYTES()
  end

  def keybytes do
    C.auth_hmacsha512_KEYBYTES()
  end

  def auth(data, key) do
    C.auth_hmacsha512(data, key)
  end

  def verify(mac, data, key) do
    C.auth_hmacsha512_verify(mac, data, key)
  end

  def init(key) do
    C.auth_hmacsha512_init(key)
  end

  def update(state, input) do
    C.auth_hmacsha512_update(state, input)
  end

  def final(state) do
    C.auth_hmacsha512_final(state)
  end

  def final_verify(state, expected) do
    C.auth_hmacsha512_final_verify(state, expected)
  end
end
