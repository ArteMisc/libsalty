defmodule Salty.Secretbox.Xsalsa20poly1305 do
  use Salty.Secretbox

  def keybytes do
    C.secretbox_xsalsa20poly1305_KEYBYTES()
  end

  def noncebytes do
    C.secretbox_xsalsa20poly1305_NONCEBYTES()
  end

  def macbytes do
    C.secretbox_xsalsa20poly1305_MACBYTES()
  end

  def seal(msg, nonce, key) do
    C.secretbox_xsalsa20poly1305_easy(msg, nonce, key)
  end

  def seal_detached(msg, nonce, key) do
    C.secretbox_xsalsa20poly1305_detached(msg, nonce, key)
  end

  def open_detached(cipher, mac, nonce, key) do
    C.secretbox_xsalsa20poly1305_open_detached(cipher, mac, nonce, key)
  end

end
