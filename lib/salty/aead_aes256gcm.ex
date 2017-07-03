defmodule Salty.Aead.Aes256gcm do
  use Salty.Aead

  def keybytes do
    C.aead_aes256gcm_KEYBYTES()
  end

  def nsecbytes do
    C.aead_aes256gcm_NSECBYTES()
  end

  def npubbytes do
    C.aead_aes256gcm_NPUBBYTES()
  end

  def abytes do
    C.aead_aes256gcm_ABYTES()
  end

  def encrypt(plain, ad, nsec, npub, key) when nsec == nil do
    C.aead_aes256gcm_encrypt(plain, ad, nsec, npub, key)
  end

  def encrypt_detached(plain, ad, nsec, npub, key) when nsec == nil do
    C.aead_aes256gcm_encrypt_detached(plain, ad, nsec, npub, key)
  end

  def decrypt_detached(nsec, cipher, mac, ad, npub, key) when nsec == nil do
    C.aead_aes256gcm_decrypt_detached(nsec, cipher, mac, ad, npub, key)
  end

end
