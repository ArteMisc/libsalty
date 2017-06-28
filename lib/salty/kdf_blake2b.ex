defmodule Salty.Kdf.Blake2b do
  use Salty.Kdf

  def bytes_min do
    C.kdf_blake2b_BYTES_MIN()
  end

  def bytes_max do
    C.kdf_blake2b_BYTES_MAX()
  end

  def contextbytes do
    C.kdf_blake2b_CONTEXTBYTES()
  end

  def keybytes do
    C.kdf_blake2b_KEYBYTES()
  end

  def derive_from_key(subkey_len, subkey_id, ctx, key) do
    C.kdf_blake2b_derive_from_key(subkey_len, subkey_id, ctx, key)
  end

end
