defmodule Salty.Auth.Hmacsha256 do
  #@behaviour Salty.Multipart.Spec

  alias Salty.Nif, as: Nif

  def bytes, do: Nif.auth_hmacsha256_BYTES()
  def key_bytes, do: Nif.auth_hmacsha256_KEYBYTES()

  def auth(data, key), do: Nif.auth_hmacsha256(data, key)
  def verify(mac, data, key), do: Nif.auth_hmacsha256_verify(mac, data, key)

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
    case Nif.auth_hmacsha256_final(state) do
      {:ok, result} -> Nif.memcmp(result, expected)
      {:error, error} -> {:error, error}
    end
  end
end
