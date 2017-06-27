defmodule Salty.Auth do
  def __using__(_opts) do
    quote do
      @behaviour Salty.Multipart.Spec
      @behaviour Salty.Auth
    end
  end

  def primitive do
    Salty.Auth.Hmacsha512256
  end

  @callback bytes() :: non_neg_integer()

  @callback keybytes() :: non_neg_integer()

  @callback auth(binary(), binary()) :: {:ok, binary()} | {:error, any()}

  @callback verify(binary(), binary(), binary()) :: :ok | {:error, any()}

  @callback init(binary()) :: {:ok, binary()} | {:error, any()}
end
