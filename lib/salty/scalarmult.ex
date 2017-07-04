defmodule Salty.Scalarmult do
  defmacro __using__(_opts) do
    quote do
      @behaviour Salty.Scalarmult
      alias Salty.Nif, as: C
    end
  end

  def primitive do
    Salty.Scalarmult.Curve25519
  end

  @callback bytes() :: non_neg_integer()

  @callback scalarbytes() :: non_neg_integer()

  @callback scalarmult_base(binary()) :: {:ok, binary()} | {:error, atom()}

  @callback scalarmult(binary(), binary()) :: {:ok, binary()} | {:error, atom()}

end
