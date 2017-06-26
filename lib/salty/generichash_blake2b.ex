defmodule Salty.Generichash.Blake2b do
  alias Salty.Nif, as: Nif

  def bytes_min do
    Nif.generichash_blake2b_BYTES_MIN()
  end

  def bytes_max do
    Nif.generichash_blake2b_BYTES_MAX()
  end

  def bytes do
    Nif.generichash_blake2b_BYTES()
  end

  def keybytes_min do
    Nif.generichash_blake2b_KEYBYTES_MIN()
  end

  def keybytes_max do
    Nif.generichash_blake2b_KEYBYTES_MAX()
  end

  def keybytes do
    Nif.generichash_blake2b_KEYBYTES()
  end

  def saltbytes do
    Nif.generichash_blake2b_SALTBYTES()
  end

  def personalbytes do
    Nif.generichash_blake2b_PERSONALBYTES()
  end

  def hash(outlen, data, key) do
    Nif.generichash_blake2b(outlen, data, key)
  end

  def hash(outlen, data, key, salt, personal) do
    Nif.generichash_blake2b_salt_personal(outlen, data, key, salt, personal)
  end

  def init(key, outlen) do
    Nif.generichash_blake2b_init(key, outlen)
  end

  def init(key, outlen, salt, personal) do
    Nif.generichash_blake2b_init_salt_personal(key, outlen, salt, personal)
  end

  def update(state, input) do
    Nif.generichash_blake2b_update(state, input)
  end

  def final(state, outlen) do
    Nif.generichash_blake2b_final(state, outlen)
  end

  def final_verify(_state, _expected) do
    :erlang.exit(:not_implemented)
  end
end
