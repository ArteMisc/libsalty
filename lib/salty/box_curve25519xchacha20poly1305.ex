defmodule Salty.Box.Curve25519xchacha20poly1305 do
  use Salty.Box

  def seedbytes do
    C.box_curve25519xchacha20poly1305_SEEDBYTES()
  end

  def publickeybytes do
    C.box_curve25519xchacha20poly1305_PUBLICKEYBYTES()
  end

  def secretkeybytes do
    C.box_curve25519xchacha20poly1305_SECRETKEYBYTES()
  end

  def noncebytes do
    C.box_curve25519xchacha20poly1305_NONCEBYTES()
  end

  def macbytes do
    C.box_curve25519xchacha20poly1305_MACBYTES()
  end

  def sealbytes do
    C.box_curve25519xchacha20poly1305_SEALBYTES()
  end

  def seed_keypair(seed) do
    C.box_curve25519xchacha20poly1305_seed_keypair(seed)
  end

  def keypair() do
    C.box_curve25519xchacha20poly1305_keypair()
  end

  def easy(msg, nonce, pk, sk) do
    C.box_curve25519xchacha20poly1305_easy(msg, nonce, pk, sk)
  end

  def detached(msg, nonce, pk, sk) do
    C.box_curve25519xchacha20poly1305_detached(msg, nonce, pk, sk)
  end

  def open_detached(cipher, mac, nonce, pk, sk) do
    C.box_curve25519xchacha20poly1305_open_detached(cipher, mac, nonce, pk, sk)
  end

  def beforenm(pk, sk) do
    C.box_curve25519xchacha20poly1305_beforenm(pk, sk)
  end

  def easy_afternm(msg, nonce, k) do
    C.box_curve25519xchacha20poly1305_easy_afternm(msg, nonce, k)
  end

  def detached_afternm(msg, nonce, k) do
    C.box_curve25519xchacha20poly1305_detached_afternm(msg, nonce, k)
  end

  def open_detached_afternm(cipher, mac, nonce, k) do
    C.box_curve25519xchacha20poly1305_open_detached_afternm(cipher, mac, nonce, k)
  end

  def seal(msg, pk) do
    C.box_curve25519xchacha20poly1305_seal(msg, pk)
  end

  def seal_open(cipher, pk, sk) do
    C.box_curve25519xchacha20poly1305_seal_open(cipher, pk, sk)
  end

end
