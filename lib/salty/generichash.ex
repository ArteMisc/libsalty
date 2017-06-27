defmodule Salty.Generichash do
  defmacro __using__(_opts) do
    quote do
      #@behaviour Salty.Multipart.Spec
      @behaviour Salty.Generichash
      alias Salty.Nif, as: C
    end
  end

  def primitive do
    Salty.Generichash.Blake2b
  end

  @callback bytes_min() :: non_neg_integer()

  @callback bytes_max() :: non_neg_integer()
  
  @callback bytes() :: non_neg_integer()

  @callback keybytes_min() :: non_neg_integer()

  @callback keybytes_max :: non_neg_integer()

  @callback keybytes :: non_neg_integer()

  @callback hash(binary(), binary(), binary()) :: {:ok, binary()} | {:error, any()}

  @callback init(binary(), non_neg_integer()) :: {:ok, binary()} | {:error, any()}

  @callback update(binary(), binary()) :: {:ok, binary()} | {:error, any()}

  @callback final(binary(), non_neg_integer()) :: {:ok, binary()} | {:error, any()}

  @callback final_verify(binary(), binary()) :: :ok | {:error, any()}
end
