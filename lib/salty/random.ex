defmodule Salty.Random do
  alias Salty.Nif, as: C

  def seedbytes do
    C.randombytes_SEEDBYTES()
  end

  def random do
    C.randombytes_random()
  end

  def stir do
    C.randombytes_stir()
  end

  def uniform(upper) do
    C.randombytes_uniform(upper)
  end

  def buf(size) when size > 0 do
    C.randombytes_buf(size)
  end

  def buf_deterministic(size, seed) when size > 0 do
    C.randombytes_buf_deterministic(size, seed)
  end

  def close do
    C.randombytes_close()
  end

end
