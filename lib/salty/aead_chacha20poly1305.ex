defmodule Salty.Aead.Chacha20poly1305 do

  alias Salty.Nif, as: Nif

  def key_bytes, do: Nif.aead_chacha20poly1305_KEYBYTES()
  def nsec_bytes, do: Nif.aead_chacha20poly1305_NSECBYTES()
  def npub_bytes, do: Nif.aead_chacha20poly1305_NPUBBYTES()
  def a_bytes, do: Nif.aead_chacha20poly1305_ABYTES()

  def encrypt(plain, ad, nsec, npub, key) when nsec == nil do
    Nif.aead_chacha20poly1305_encrypt(plain, ad, nsec, npub, key)
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
    Nif.aead_chacha20poly1305_decrypt_detached(nsec, cipher, mac, ad, npub, key)
  end

end
