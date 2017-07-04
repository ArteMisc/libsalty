defmodule Salty.Scalarmult.Curve25519 do
  use Salty.Scalarmult

  def bytes do
    C.scalarmult_curve25519_BYTES()
  end

  def scalarbytes do
    C.scalarmult_curve25519_SCALARBYTES()
  end

  def scalarmult_base(n) do
    C.scalarmult_curve25519_base(n)
  end

  def scalarmult(n, p) do
    C.scalarmult_curve25519(n, p)
  end

end
