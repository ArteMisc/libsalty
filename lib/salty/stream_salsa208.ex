defmodule Salty.Stream.Salsa208 do
  use Salty.Stream

  def noncebytes do
    C.stream_salsa208_NONCEBYTES()
  end

  def keybytes do
    C.stream_salsa208_KEYBYTES()
  end

  def stream(outlen, nonce, key) do
    C.stream_salsa208(outlen, nonce, key)
  end

  def xor(m, nonce, key) do
    C.stream_salsa208_xor(m, nonce, key)
  end

end
