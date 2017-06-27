defmodule Salty.Hash.Sha512 do
  use Salty.Hash

  def bytes do
    C.hash_sha512_BYTES()
  end

  def hash(data) do
    C.hash_sha512(data)
  end

  def verify(data, expected) do
    C.hash_sha512_verify(data, expected)
  end

  def init do
    C.hash_sha512_init()
  end

  def update(state, data) do
    C.hash_sha512_update(state, data)
  end

  def final(state) do
    C.hash_sha512_final(state)
  end

  def final_verify(state, expected) do
    C.hash_sha512_final_verify(state, expected)
  end

end
