defmodule Salty.Secretbox do
  defmacro __using__(_opts) do
    quote do
      @behaviour Salty.Secretbox
      alias Salty.Nif, as: C

      def open(cipher, nonce, key) do
        mac_size = macbytes()
        <<mac::binary-size(mac_size),
          data::binary>> = cipher
        open_detached(data, mac, nonce, key)
      end

    end
  end

  def primitive do
    Salty.Secretbox.Xsalsa20poly1305
  end

  @callback keybytes() :: non_neg_integer()

  @callback noncebytes() :: non_neg_integer()

  @callback macbytes() :: non_neg_integer()

  @callback seal(binary(), binary(), binary()) :: {:ok, binary()} | {:error, atom()}

  @callback seal_detached(binary(), binary(), binary()) :: {:ok, binary(), binary()} | {:error, atom()}

  @callback open_detached(binary(), binary(), binary(), binary()) :: {:ok, binary()} | {:error, atom()}
end
