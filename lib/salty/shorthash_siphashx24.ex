defmodule Salty.Shorthash.Siphashx24 do
  use Salty.Shorthash

  def bytes do
    C.shorthash_siphashx24_BYTES()
  end

  def keybytes do
    C.shorthash_siphashx24_KEYBYTES()
  end

  def hash(data, key) do
    C.shorthash_siphashx24(data, key)
  end

end
