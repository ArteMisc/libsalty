defmodule Salty.Aead.Aes256gcm do
  use Salty.Aead

  def key_bytes do
    C.aead_aes256gcm_KEYBYTES()
  end

  def nsec_bytes do
    C.aead_aes256gcm_NSECBYTES()
  end

  def npub_bytes do
    C.aead_aes256gcm_NPUBBYTES()
  end

  def a_bytes do
    C.aead_aes256gcm_ABYTES()
  end

  def encrypt(plain, ad, nsec, npub, key) when nsec == nil do
    C.aead_aes256gcm_encrypt(plain, ad, nsec, npub, key)
  end

  def decrypt_detached(nsec, cipher, mac, ad, npub, key) when nsec == nil do
    C.aead_aes256gcm_decrypt_detached(nsec, cipher, mac, ad, npub, key)
  end

end
