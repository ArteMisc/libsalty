defmodule Salty.Sign.Ed25519 do
  use Salty.Sign

  def bytes do
    C.sign_ed25519_BYTES()
  end

  def seedbytes do
    C.sign_ed25519_SEEDBYTES()
  end

  def publickeybytes do
    C.sign_ed25519_PUBLICKEYBYTES()
  end

  def secretkeybytes do
    C.sign_ed25519_SECRETKEYBYTES()
  end

  def seed_keypair(seed) do
    C.sign_ed25519_seed_keypair(seed)
  end

  def keypair do
    C.sign_ed25519_keypair()
  end

  def sign(data, sk) do
    C.sign_ed25519(data, sk)
  end

  def sign_detached(data, sk) do
    C.sign_ed25519_detached(data, sk)
  end

  def verify_detached(sig, data, pk) do
    C.sign_ed25519_verify_detached(sig, data, pk)
  end

  def init() do
    C.sign_ed25519ph_init()
  end

  def update(state, data) do
    C.sign_ed25519ph_update(state, data)
  end

  def final(state, sk) do
    C.sign_ed25519ph_final_create(state, sk)
  end

  def final_verify(state, sig, pk) do
    C.sign_ed25519ph_final_verify(state, sig, pk)
  end

end
