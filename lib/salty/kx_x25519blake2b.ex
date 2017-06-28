defmodule Salty.Kx.X25519blake2b do
  use Salty.Kx

  def publickeybytes do
    C.kx_PUBLICKEYBYTES()
  end

  def secretkeybytes do
    C.kx_SECRETKEYBYTES()
  end

  def seedbytes do
    C.kx_SEEDBYTES()
  end

  def sessionkeybytes do
    C.kx_SESSIONKEYBYTES()
  end

  def seed_keypair(seed) do
    C.kx_seed_keypair(seed)
  end

  def keypair do
    C.kx_keypair()
  end

  def client_session_keys(client_pk, client_sk, server_pk) do
    C.kx_client_session_keys(client_pk, client_sk, server_pk)
  end

  def server_session_keys(server_pk, server_sk, client_pk) do
    C.kx_server_session_keys(server_pk, server_sk, client_pk)
  end

end
