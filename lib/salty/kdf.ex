defmodule Salty.Kdf do
  defmacro __using__(_opts) do
    quote do
      @behaviour Salty.Kdf
      alias Salty.Nif, as: C
    end
  end

  def primitive do
    Salty.Kdf.Blake2b
  end

  @callback bytes_min() :: pos_integer()

  @callback bytes_max() :: pos_integer()

  @callback contextbytes() :: pos_integer()

  @callback keybytes() :: pos_integer()

  @callback derive_from_key(pos_integer(), non_neg_integer(), binary(), binary()) :: {:ok, binary()} | {:error, atom()}

end
