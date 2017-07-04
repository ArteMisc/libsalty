defmodule Salty.Stream.Chacha20Ietf do
  use Salty.Stream

  def noncebytes do
    C.stream_chacha20_ietf_NONCEBYTES()
  end

  def keybytes do
    C.stream_chacha20_ietf_KEYBYTES()
  end

  def stream(outlen, nonce, key) do
    C.stream_chacha20_ietf(outlen, nonce, key)
  end

  def xor(m, nonce, key) do
    C.stream_chacha20_ietf_xor(m, nonce, key)
  end

  def xor_ic(m, nonce, ic, key) do
    C.stream_chacha20_ietf_xor_ic(m, nonce, ic, key)
  end

end
