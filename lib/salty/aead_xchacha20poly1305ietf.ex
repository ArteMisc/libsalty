defmodule Salty.Aead.XChacha20poly1305Ietf do

  alias Salty.Nif, as: Nif

  def key_bytes, do: Nif.aead_xchacha20poly1305_ietf_KEYBYTES()
  def nsec_bytes, do: Nif.aead_xchacha20poly1305_ietf_NSECBYTES()
  def npub_bytes, do: Nif.aead_xchacha20poly1305_ietf_NPUBBYTES()
  def a_bytes, do: Nif.aead_xchacha20poly1305_ietf_ABYTES()

  def encrypt(plain, ad, nsec, npub, key) when nsec == nil do
    Nif.aead_xchacha20poly1305_ietf_encrypt(plain, ad, nsec, npub, key)
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
    Nif.aead_xchacha20poly1305_ietf_decrypt_detached(nsec, cipher, mac, ad, npub, key)
  end

end
