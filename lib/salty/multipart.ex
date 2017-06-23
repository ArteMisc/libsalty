defprotocol Salty.Multipart do
  def update(multipart, data)

  def final(multipart)

  def final_verify(multipart, expected)
end

defmodule Salty.Multipart.Spec do
  @callback do_update(binary(), iodata()) :: binary()
  @callback do_final(binary()) :: binary()
end

defimpl Salty.Multipart, for: Any do
  def update(_, _), do: :erlang.exit(:salty_multipart_not_implemented)
  def final(_), do: :erlang.exit(:salty_multipart_not_implemented)
  def final_verify(_, _), do: :erlang.exit(:salty_multipart_not_implemented)
end
