defmodule Salty.Auth.Hmacsha512 do
  @behaviour Salty.Multipart.Spec

  alias Salty.Nif, as: Nif

  def bytes do
    Nif.auth_hmacsha512_BYTES()
  end

  def keybytes do
    Nif.auth_hmacsha512_KEYBYTES()
  end

  def auth(data, key) do
    Nif.auth_hmacsha512(data, key)
  end

  def verify(mac, data, key) do
    Nif.auth_hmacsha512_verify(mac, data, key)
  end

  def init(key) do
    Nif.auth_hmacsha512_init(key)
  end

  def update(state, input) do
    Nif.auth_hmacsha512_update(state, input)
  end

  def final(state) do
    Nif.auth_hmacsha512_final(state)
  end

  def final_verify(state, expected) do
    Nif.auth_hmacsha512_final_verify(state, expected)
  end
end
