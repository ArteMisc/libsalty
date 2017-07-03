defmodule Salty.Aead do
  defmacro __using__(_opts) do
    quote do
      @behaviour Salty.Aead
      alias Salty.Nif, as: C

      def decrypt(nsec, cipher, ad, npub, key) do
        mac_size = abytes()
        <<mac::binary-size(mac_size),
          data::binary>> = cipher
        decrypt_detached(nsec, data, mac, ad, npub, key)
      end

    end
  end

  @callback keybytes() :: non_neg_integer()

  @callback nsecbytes() :: non_neg_integer()

  @callback npubbytes() :: non_neg_integer()

  @callback abytes() :: non_neg_integer()

  @callback encrypt(binary(), binary(), binary() | nil, binary(), binary()) :: {:ok, binary()} | {:error, atom()}

  @callback encrypt_detached(binary(), binary(), binary() | nil, binary(), binary()) :: {:ok, binary(), binary()} | {:error, atom()}

  @callback decrypt(binary() | nil, binary(), binary(), binary(), binary()) :: {:ok, binary()} | {:error, atom()}

  @callback decrypt_detached(binary() | nil, binary(), binary(), binary(), binary(), binary()) :: {:ok, binary()} | {:error, atom()}
end
