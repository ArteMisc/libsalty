defmodule Salty.Stream do
  defmacro __using__(_opts) do
    quote do
      @behaviour Salty.Stream
      alias Salty.Nif, as: C
    end
  end

  def primitive do
    Salty.Stream.Xsalsa20
  end

  @callback noncebytes() :: non_neg_integer()

  @callback keybytes() :: non_neg_integer()

  @callback stream(pos_integer(), binary(), binary()) :: {:ok, binary()} | {:error, atom()}

  @callback xor(binary(), binary(), binary()) :: {:ok, binary()} | {:error, atom()}

end
