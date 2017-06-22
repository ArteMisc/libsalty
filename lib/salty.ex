defmodule Salty do
  @moduledoc """
  Salty 
  """

  alias Salty.Nif, as: Nif

  @doc """
  Salty.equals compares binaries a and b in a side-channel free way.
  """
  def equals(a, b), do: Nif.memcmp(a, b)

  #def keygen(size), do: Nif.randombytes(size)
end
