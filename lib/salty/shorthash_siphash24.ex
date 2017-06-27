defmodule Salty.Shorthash.Siphash24 do
  use Salty.Shorthash

  def bytes do
    C.shorthash_siphash24_BYTES()
  end

  def keybytes do
    C.shorthash_siphash24_KEYBYTES()
  end

  def hash(data, key) do
    C.shorthash_siphash24(data, key)
  end

end
