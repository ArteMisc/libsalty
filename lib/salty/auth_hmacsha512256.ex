defmodule Salty.Auth.Hmacsha512256 do
  #@behaviour Salty.Multipart.Spec

  alias Salty.Nif, as: Nif

  def bytes do
    Nif.auth_hmacsha512256_BYTES()
  end

  def key_bytes do
    Nif.auth_hmacsha512256_KEYBYTES()
  end

  def auth(data, key) do
    Nif.auth_hmacsha512256(data, key)
  end

  def verify(mac, data, key) do
    Nif.auth_hmacsha512256_verify(mac, data, key)
  end

  def init(key) do
    Nif.auth_hmacsha512256_init(key)
  end

  def update(state, input) do
    Nif.auth_hmacsha512256_update(state, input)
  end

  def final(state) do
    Nif.auth_hmacsha512256_final(state)
  end

  def final_verify(state, expected) do
    Nif.auth_hmacsha512256_final_verify(state, expected)
  end
end
