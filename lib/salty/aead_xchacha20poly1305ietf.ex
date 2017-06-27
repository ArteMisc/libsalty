defmodule Salty.Aead.Xchacha20poly1305Ietf do
  use Salty.Aead

  def key_bytes do
    C.aead_xchacha20poly1305_ietf_KEYBYTES()
  end

  def nsec_bytes do
    C.aead_xchacha20poly1305_ietf_NSECBYTES()
  end

  def npub_bytes do
    C.aead_xchacha20poly1305_ietf_NPUBBYTES()
  end

  def a_bytes do
    C.aead_xchacha20poly1305_ietf_ABYTES()
  end

  def encrypt(plain, ad, nsec, npub, key) when nsec == nil do
    C.aead_xchacha20poly1305_ietf_encrypt(plain, ad, nsec, npub, key)
  end

  def decrypt_detached(nsec, cipher, mac, ad, npub, key) when nsec == nil do
    C.aead_xchacha20poly1305_ietf_decrypt_detached(nsec, cipher, mac, ad, npub, key)
  end

end
