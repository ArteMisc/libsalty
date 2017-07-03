defmodule Salty.Aead.Chacha20poly1305Ietf do
  use Salty.Aead

  def keybytes do
    C.aead_chacha20poly1305_ietf_KEYBYTES()
  end

  def nsecbytes do
    C.aead_chacha20poly1305_ietf_NSECBYTES()
  end

  def npubbytes do
    C.aead_chacha20poly1305_ietf_NPUBBYTES()
  end

  def abytes do
    C.aead_chacha20poly1305_ietf_ABYTES()
  end

  def encrypt(plain, ad, nsec, npub, key) when nsec == nil do
    C.aead_chacha20poly1305_ietf_encrypt(plain, ad, nsec, npub, key)
  end

  def encrypt_detached(plain, ad, nsec, npub, key) when nsec == nil do
    C.aead_chacha20poly1305_ietf_encrypt_detached(plain, ad, nsec, npub, key)
  end

  def decrypt_detached(nsec, cipher, mac, ad, npub, key) when nsec == nil do
    C.aead_chacha20poly1305_ietf_decrypt_detached(nsec, cipher, mac, ad, npub, key)
  end

end
