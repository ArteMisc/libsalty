defmodule Salty.Stream.Chacha20 do
  use Salty.Stream

  def noncebytes do
    C.stream_chacha20_NONCEBYTES()
  end

  def keybytes do
    C.stream_chacha20_KEYBYTES()
  end

  def stream(outlen, nonce, key) do
    C.stream_chacha20(outlen, nonce, key)
  end

  def xor(m, nonce, key) do
    C.stream_chacha20_xor(m, nonce, key)
  end

  def xor_ic(m, nonce, ic, key) do
    C.stream_chacha20_xor_ic(m, nonce, ic, key)
  end

end
