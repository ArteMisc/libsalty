defprotocol Salty.Multipart do
  def init

  def update(multipart, data)

  def final(multipart)

  def finalVerify(multipart, expected)
end

defimpl Salty.Multipart, for: Any do
  def init, do: :erlang.exit(:salty_multipart_not_implemented)
  def update(_, _), do: :erlang.exit(:salty_multipart_not_implemented)
  def final(_), do: :erlang.exit(:salty_multipart_not_implemented)
  def finalVerify(_, _), do: :erlang.exit(:salty_multipart_not_implemented)
end
