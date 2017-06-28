defmodule Salty.Auth do
  defmacro __using__(_opts) do
    quote do
      @behaviour Salty.Multipart.Spec
      @behaviour Salty.Auth
      alias Salty.Nif, as: C
    end
  end

  def primitive do
    Salty.Auth.Hmacsha512256
  end

  @callback bytes() :: non_neg_integer()

  @callback keybytes() :: non_neg_integer()

  @callback auth(binary(), binary()) :: {:ok, binary()} | {:error, atom()}

  @callback verify(binary(), binary(), binary()) :: :ok | {:error, atom()}

  @callback init(binary()) :: {:ok, binary()} | {:error, atom()}
end
