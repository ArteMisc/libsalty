defmodule Salty.Aead.Chacha20poly1305 do
  use Salty.Aead

  def key_bytes do
    C.aead_chacha20poly1305_KEYBYTES()
  end

  def nsec_bytes do
    C.aead_chacha20poly1305_NSECBYTES()
  end

  def npub_bytes do
    C.aead_chacha20poly1305_NPUBBYTES()
  end

  def a_bytes do
    C.aead_chacha20poly1305_ABYTES()
  end

  def encrypt(plain, ad, nsec, npub, key) when nsec == nil do
    C.aead_chacha20poly1305_encrypt(plain, ad, nsec, npub, key)
  end

  def decrypt_detached(nsec, cipher, mac, ad, npub, key) when nsec == nil do
    C.aead_chacha20poly1305_decrypt_detached(nsec, cipher, mac, ad, npub, key)
  end

end
