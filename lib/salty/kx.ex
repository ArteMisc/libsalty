defmodule Salty.Kx do
  defmacro __using__(_opts) do
    quote do
      @behaviour Salty.Kx
      alias Salty.Nif, as: C
    end
  end

  def primitive do
    Salty.Kx.X25519blake2b
  end

  @callback publickeybytes() :: pos_integer()

  @callback secretkeybytes() :: pos_integer()

  @callback seedbytes() :: pos_integer()

  @callback sessionkeybytes() :: pos_integer()

  @callback seed_keypair(binary()) :: {:ok, binary(), binary()} | {:error, atom()}

  @callback keypair() :: {:ok, binary(), binary()} | {:error, atom()}

  @callback client_session_keys(binary(), binary(), binary()) :: {:ok, binary(), binary()} | {:error, atom()}

  @callback server_session_keys(binary(), binary(), binary()) :: {:ok, binary(), binary()} | {:error, atom()}

end
