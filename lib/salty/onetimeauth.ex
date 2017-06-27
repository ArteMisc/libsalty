defmodule Salty.Onetimeauth do
  defmacro __using__(_opts) do
    quote do
      @behaviour Salty.Multipart.Spec
      @behaviour Salty.Auth
      alias Salty.Nif, as: C
    end
  end

  def primitive do
    Salty.Onetimeauth.Poly1305
  end

end
