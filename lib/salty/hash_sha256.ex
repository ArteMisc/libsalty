defmodule Salty.Hash.Sha256 do
  use Salty.Hash

  def bytes do
    C.hash_sha256_BYTES()
  end

  def hash(data) do
    C.hash_sha256(data)
  end

  def verify(data, expected) do
    C.hash_sha256_verify(data, expected)
  end

  def init do
    C.hash_sha256_init()
  end

  def update(state, data) do
    C.hash_sha256_update(state, data)
  end

  def final(state) do
    C.hash_sha256_final(state)
  end

  def final_verify(state, expected) do
    C.hash_sha256_final_verify(state, expected)
  end

end
