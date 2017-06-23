defmodule Salty.Auth.Hmacsha256 do

  alias Salty.Nif, as: Nif

  def bytes, do: Nif.auth_hmacsha256_BYTES()
  def key_bytes, do: Nif.auth_hmacsha256_KEYBYTES()

  def auth(data, key), do: Nif.auth_hmacsha256(data, key)
  def verify(mac, data, key), do: Nif.auth_hmacsha256_verify(mac, data, key)

end
