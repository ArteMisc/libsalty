defmodule Salty.Auth.Hmacsha256 do
  #@behaviour Salty.Multipart.Spec

  alias Salty.Nif, as: Nif

  def bytes do
    Nif.auth_hmacsha256_BYTES()
  end

  def key_bytes do
    Nif.auth_hmacsha256_KEYBYTES()
  end

  def auth(data, key) do
    Nif.auth_hmacsha256(data, key)
  end

  def verify(mac, data, key) do
    Nif.auth_hmacsha256_verify(mac, data, key)
  end

  def init(key) do
    Nif.auth_hmacsha256_init(key)
  end

  def update(state, input) do
    Nif.auth_hmacsha256_update(state, input)
  end

  def final(state) do
    Nif.auth_hmacsha256_final(state)
  end

  def final_verify(state, expected) do
    Nif.auth_hmacsha256_final_verify(state, expected)
  end
end
