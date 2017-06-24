defmodule Salty.Aead.Aes256gcm do

  alias Salty.Nif, as: Nif

  def key_bytes, do: Nif.aead_aes256gcm_KEYBYTES()
  def nsec_bytes, do: Nif.aead_aes256gcm_NSECBYTES()
  def npub_bytes, do: Nif.aead_aes256gcm_NPUBBYTES()
  def a_bytes, do: Nif.aead_aes256gcm_ABYTES()

  def encrypt(plain, ad, nsec, npub, key) when nsec == nil do
    Nif.aead_aes256gcm_encrypt(plain, ad, nsec, npub, key)
  end

  def encrypt_detached(plain, ad, nsec, npub, key) do
    mac_size = a_bytes()
    case encrypt(plain, ad, nsec, npub, key) do
      {:ok, <<mac::binary-size(mac_size),cipher::binary>>} -> {:ok, mac, cipher}
      error -> error
    end
  end

  def decrypt(nsec, cipher, ad, npub, key) do
    mac_size = a_bytes()
    <<mac::binary-size(mac_size),
      data::binary>> = cipher
    decrypt_detached(nsec, data, mac, ad, npub, key)
  end

  def decrypt_detached(nsec, cipher, mac, ad, npub, key) when nsec == nil do
    Nif.aead_aes256gcm_decrypt_detached(nsec, cipher, mac, ad, npub, key)
  end

end
