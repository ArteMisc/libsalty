defmodule Salty.Sign do
  defmacro __using__(_opts) do
    quote do
      @behaviour Salty.Multipart.SignSpec
      @behaviour Salty.Sign
      alias Salty.Nif, as: C

      def sk_to_pk(sk) do
        seedlen = seedbytes()
        publen = publickeybytes()
        <<_ :: binary-size(seedlen),
          p :: binary-size(publen)>> = sk
        p
      end

      def sk_to_seed(sk) do
        seedlen = seedbytes()
        publen = publickeybytes()
        <<s :: binary-size(seedlen),
          _ :: binary-size(publen)>> = sk
        s
      end

      def open(sm, pk) do
        siglen = bytes()
        <<sig  :: binary-size(siglen),
          data :: binary>> = sm
        case verify_detached(sig, data, pk) do
          :ok -> {:ok, data}
          {:error, error} -> {:error, error}
        end
      end
    end
  end

  def primitive do
    Salty.Sign.Ed25519
  end

  @callback bytes() :: non_neg_integer()

  @callback seedbytes() :: non_neg_integer()

  @callback publickeybytes() :: non_neg_integer()

  @callback secretkeybytes() :: non_neg_integer()

  @callback seed_keypair(binary()) :: {:ok, binary(), binary()} | {:error, atom()}

  @callback keypair() :: {:ok, binary(), binary()} | {:error, atom()}

  @callback sign(binary(), binary()) :: {:ok, binary()} | {:error, atom()}

  @callback sign_detached(binary(), binary()) :: {:ok, binary()} | {:error, atom()}

  @callback open(binary(), binary()) :: {:ok, binary()} | {:error, atom()}

  @callback verify_detached(binary(), binary(), binary()) :: :ok | {:error, atom()}

  @callback init() :: {:ok, binary()} | {:error, atom()}

end
