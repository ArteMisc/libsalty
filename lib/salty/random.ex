defmodule Salty.Random do
  
  alias Salty.Nif, as: Nif

  def seed_bytes, do: Nif.randombytes_SEEDBYTES()

  def random, do: Nif.randombytes_random()

  def stir, do: Nif.randombytes_stir()

  def uniform(upper), do: Nif.randombytes_uniform(upper)

  def buf(size) when size > 0, do: Nif.randombytes_buf(size)

  def buf_deterministic(size, seed) when size > 0 do
    Nif.randombytes_buf_deterministic(size, seed)
  end

  def close, do: Nif.randombytes_close()

end
