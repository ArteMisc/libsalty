defmodule Salty.Core do
  alias Salty.Nif, as: Nif

  def hchacha20(input, key, const) do
    Nif.core_hchacha20(input, key, const)
  end

  def hsalsa20(input, key, const) do
    Nif.core_hsalsa20(input, key, const)
  end
end
