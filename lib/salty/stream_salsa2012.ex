defmodule Salty.Stream.Salsa2012 do
  use Salty.Stream

  def noncebytes do
    C.stream_salsa2012_NONCEBYTES()
  end

  def keybytes do
    C.stream_salsa2012_KEYBYTES()
  end

  def stream(outlen, nonce, key) do
    C.stream_salsa2012(outlen, nonce, key)
  end

  def xor(m, nonce, key) do
    C.stream_salsa2012_xor(m, nonce, key)
  end

end
