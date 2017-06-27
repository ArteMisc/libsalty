defmodule Salty.Onetimeauth.Poly1305 do
  use Salty.Onetimeauth

  def bytes do
    C.onetimeauth_poly1305_BYTES()
  end

  def keybytes do
    C.onetimeauth_poly1305_KEYBYTES()
  end

  def auth(data, key) do
    C.onetimeauth_poly1305(data, key)
  end

  def verify(mac, data, key) do
    C.onetimeauth_poly1305_verify(mac, data, key)
  end

  def init(key) do
    C.onetimeauth_poly1305_init(key)
  end

  def update(state, input) do
    C.onetimeauth_poly1305_update(state, input)
  end

  def final(state) do
    C.onetimeauth_poly1305_final(state)
  end

  def final_verify(state, expected) do
    C.onetimeauth_poly1305_final_verify(state, expected)
  end

end
