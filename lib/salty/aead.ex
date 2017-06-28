defmodule Salty.Aead do
  defmacro __using__(_opts) do
    quote do
      @behaviour Salty.Aead
      alias Salty.Nif, as: C

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

    end
  end

  @callback key_bytes() :: non_neg_integer()

  @callback nsec_bytes() :: non_neg_integer()

  @callback npub_bytes() :: non_neg_integer()

  @callback a_bytes() :: non_neg_integer()

  @callback encrypt(binary(), binary(), binary() | nil, binary(), binary()) :: {:ok, binary()} | {:error, atom()}

  @callback decrypt_detached(binary() | nil, binary(), binary(), binary(), binary(), binary()) :: {:ok, binary()} | {:error, atom()}
end
