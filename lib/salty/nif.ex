defmodule Salty.Nif do
  @moduledoc false

  @doc """
  load_nif is called when Salty.Application is started. It loads the libary and
  binds the Elixir module methods to erl_nif calls.
  """
  def load_nif do
    path = :filename.join([:code.priv_dir(:salty), :erlang.system_info(:system_architecture), "salty_nif"])
    case :erlang.load_nif(path, 0) do
      :ok -> :ok
      error -> {:error, error}
    end
  end

  #def func, do: :erlang.exit(:salty_nif_not_loaded)

  def init, do: :erlang.exit(:salty_nif_not_loaded)
  def memcmp(_, _), do: :erlang.exit(:salty_nif_not_loaded)

  def aead_aes256gcm_KEYBYTES, do: :erlang.exit(:salty_nif_not_loaded)
  def aead_aes256gcm_NSECBYTES, do: :erlang.exit(:salty_nif_not_loaded)
  def aead_aes256gcm_NPUBBYTES, do: :erlang.exit(:salty_nif_not_loaded)
  def aead_aes256gcm_ABYTES, do: :erlang.exit(:salty_nif_not_loaded)
  def aead_aes256gcm_is_available, do: :erlang.exit(:salty_nif_not_loaded)

  def aead_chacha20poly1305_KEYBYTES, do: :erlang.exit(:salty_nif_not_loaded)
  def aead_chacha20poly1305_NSECBYTES, do: :erlang.exit(:salty_nif_not_loaded)
  def aead_chacha20poly1305_NPUBBYTES, do: :erlang.exit(:salty_nif_not_loaded)
  def aead_chacha20poly1305_ABYTES, do: :erlang.exit(:salty_nif_not_loaded)
  def aead_chacha20poly1305_encrypt(_,_,_,_,_), do: :erlang.exit(:salty_nif_not_loaded)
  def aead_chacha20poly1305_decrypt_detached(_,_,_,_,_,_), do: :erlang.exit(:salty_nif_not_loaded)

  def aead_xchacha20poly1305_ietf_KEYBYTES, do: :erlang.exit(:salty_nif_not_loaded)
  def aead_xchacha20poly1305_ietf_NSECBYTES, do: :erlang.exit(:salty_nif_not_loaded)
  def aead_xchacha20poly1305_ietf_NPUBBYTES, do: :erlang.exit(:salty_nif_not_loaded)
  def aead_xchacha20poly1305_ietf_ABYTES, do: :erlang.exit(:salty_nif_not_loaded)

  def auth_hmacsha256_BYTES, do: :erlang.exit(:salty_nif_not_loaded)
  def auth_hmacsha256_KEYBYTES, do: :erlang.exit(:salty_nif_not_loaded)
  def auth_hmacsha256(_, _), do: :erlang.exit(:salty_nif_not_loaded)
  def auth_hmacsha256_verify(_, _, _), do: :erlang.exit(:salty_nif_not_loaded)
end
