defmodule Salty.Core do
  alias Salty.Nif, as: C

  def hchacha20(input, key, const) do
    C.core_hchacha20(input, key, const)
  end

  def hsalsa20(input, key, const) do
    C.core_hsalsa20(input, key, const)
  end
end
