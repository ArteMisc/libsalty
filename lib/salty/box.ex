defmodule Salty.Box do
  defmacro __using__(_opts) do
    quote do
      @behaviour Salty.Box
      alias Salty.Nif, as: C

      def open_easy(cipher, nonce, pk, sk) do
        mac_size = macbytes()
        <<mac::binary-size(mac_size),
          data::binary>> = cipher
        open_detached(data, mac, nonce, pk, sk)
      end

      def open_easy_afternm(cipher, nonce, k) do
        mac_size = macbytes()
        <<mac::binary-size(mac_size),
          data::binary>> = cipher
        open_detached_afternm(data, mac, nonce, k)
      end
    end
  end

  def primitive do
    Salty.Box.Curve25519xsalsa20poly1305
  end

  @callback seedbytes() :: non_neg_integer()

  @callback publickeybytes() :: non_neg_integer()

  @callback secretkeybytes() :: non_neg_integer()

  @callback noncebytes() :: non_neg_integer()

  @callback macbytes() :: non_neg_integer()

  @callback sealbytes() :: non_neg_integer()

  @callback seed_keypair(binary()) :: {:ok, binary(), binary()} | {:error, atom()}

  @callback keypair() :: {:ok, binary(), binary()} | {:error, atom()}

  @callback easy(binary(), binary(), binary(), binary()) :: {:ok, binary()} | {:error, atom()}

  @callback open_easy(binary(), binary(), binary(), binary()) :: {:ok, binary()} | {:error, atom()}

  @callback detached(binary(), binary(), binary(), binary()) :: {:ok, binary(), binary()} | {:error, atom()}

  @callback open_detached(binary(), binary(), binary(), binary(), binary()) :: {:ok, binary()} | {:error, atom()}

  @callback beforenm(binary(), binary()) :: {:ok, binary()} | {:error, atom()}

  @callback easy_afternm(binary(), binary(), binary()) :: {:ok, binary()} | {:error, atom()}

  @callback open_easy_afternm(binary(), binary(), binary()) :: {:ok, binary()} | {:error, atom()}

  @callback detached_afternm(binary(), binary(), binary()) :: {:ok, binary(), binary()} | {:error, atom()}

  @callback open_detached_afternm(binary(), binary(), binary(), binary()) :: {:ok, binary()} | {:error, atom()}

  @callback seal(binary(), binary()) :: {:ok, binary()} | {:error, atom()}

  @callback seal_open(binary(), binary(), binary()) :: {:ok, binary()} | {:error, atom()}

end
