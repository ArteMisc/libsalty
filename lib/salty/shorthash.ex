defmodule Salty.Shorthash do
  defmacro __using__(_opts) do
    quote do
      @behaviour Salty.Shorthash
      alias Salty.Nif, as: C
    end
  end

  @callback bytes() :: non_neg_integer()

  @callback keybytes() :: non_neg_integer()

  @callback hash(binary(), binary()) :: {:ok, binary()} | {:error, atom()}

end
