defmodule Salty.Hash do
  defmacro __using__(_opts) do
    quote do
      @behaviour Salty.Multipart.Spec
      @behaviour Salty.Hash
      alias Salty.Nif, as: C
    end
  end

  def primitive do
    Salty.Hash.Sha512
  end

  @callback bytes() :: non_neg_integer()

  @callback hash(binary()) :: {:ok, binary()} | {:error, atom()}

  @callback verify(binary(), binary()) :: :ok | {:error, atom()}

  @callback init() :: {:ok, binary()} | {:error, atom()}

end
