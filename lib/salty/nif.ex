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

  def init, do: :erlang.exit(:salty_nif_not_loaded)
  def memcmp(_, _), do: :erlang.exit(:salty_nif_not_loaded)

  def aead_aes256gcm_KEYBYTES, do: :erlang.exit(:salty_nif_not_loaded)
  def aead_aes256gcm_NSECBYTES, do: :erlang.exit(:salty_nif_not_loaded)
  def aead_aes256gcm_NPUBBYTES, do: :erlang.exit(:salty_nif_not_loaded)
  def aead_aes256gcm_ABYTES, do: :erlang.exit(:salty_nif_not_loaded)
  def aead_aes256gcm_is_available, do: :erlang.exit(:salty_nif_not_loaded)
  def aead_aes256gcm_encrypt(_,_,_,_,_), do: :erlang.exit(:salty_nif_not_loaded)
  def aead_aes256gcm_decrypt_detached(_,_,_,_,_,_), do: :erlang.exit(:salty_nif_not_loaded)

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
  def aead_xchacha20poly1305_ietf_encrypt(_,_,_,_,_), do: :erlang.exit(:salty_nif_not_loaded)
  def aead_xchacha20poly1305_ietf_decrypt_detached(_,_,_,_,_,_), do: :erlang.exit(:salty_nif_not_loaded)

  def auth_hmacsha256_BYTES, do: :erlang.exit(:salty_nif_not_loaded)
  def auth_hmacsha256_KEYBYTES, do: :erlang.exit(:salty_nif_not_loaded)
  def auth_hmacsha256(_,_), do: :erlang.exit(:salty_nif_not_loaded)
  def auth_hmacsha256_verify(_,_,_), do: :erlang.exit(:salty_nif_not_loaded)
  def auth_hmacsha256_init(_), do: :erlang.exit(:salty_nif_not_loaded)
  def auth_hmacsha256_update(_,_), do: :erlang.exit(:salty_nif_not_loaded)
  def auth_hmacsha256_final(_), do: :erlang.exit(:salty_nif_not_loaded)
  def auth_hmacsha256_final_verify(_,_), do: :erlang.exit(:salty_nif_not_loaded)

  def auth_hmacsha512_BYTES, do: :erlang.exit(:salty_nif_not_loaded)
  def auth_hmacsha512_KEYBYTES, do: :erlang.exit(:salty_nif_not_loaded)
  def auth_hmacsha512(_,_), do: :erlang.exit(:salty_nif_not_loaded)
  def auth_hmacsha512_verify(_,_,_), do: :erlang.exit(:salty_nif_not_loaded)
  def auth_hmacsha512_init(_), do: :erlang.exit(:salty_nif_not_loaded)
  def auth_hmacsha512_update(_,_), do: :erlang.exit(:salty_nif_not_loaded)
  def auth_hmacsha512_final(_), do: :erlang.exit(:salty_nif_not_loaded)
  def auth_hmacsha512_final_verify(_,_), do: :erlang.exit(:salty_nif_not_loaded)

  def auth_hmacsha512256_BYTES, do: :erlang.exit(:salty_nif_not_loaded)
  def auth_hmacsha512256_KEYBYTES, do: :erlang.exit(:salty_nif_not_loaded)
  def auth_hmacsha512256(_,_), do: :erlang.exit(:salty_nif_not_loaded)
  def auth_hmacsha512256_verify(_,_,_), do: :erlang.exit(:salty_nif_not_loaded)
  def auth_hmacsha512256_init(_), do: :erlang.exit(:salty_nif_not_loaded)
  def auth_hmacsha512256_update(_,_), do: :erlang.exit(:salty_nif_not_loaded)
  def auth_hmacsha512256_final(_), do: :erlang.exit(:salty_nif_not_loaded)
  def auth_hmacsha512256_final_verify(_,_), do: :erlang.exit(:salty_nif_not_loaded)

  def core_hchacha20(_,_,_), do: :erlang.exit(:salty_nif_not_loaded)
  def core_hsalsa20(_,_,_), do: :erlang.exit(:salty_nif_not_loaded)

  def generichash_blake2b_BYTES_MIN, do: :erlang.exit(:salty_nif_not_loaded)
  def generichash_blake2b_BYTES_MAX, do: :erlang.exit(:salty_nif_not_loaded)
  def generichash_blake2b_BYTES, do: :erlang.exit(:salty_nif_not_loaded)
  def generichash_blake2b_KEYBYTES_MIN, do: :erlang.exit(:salty_nif_not_loaded)
  def generichash_blake2b_KEYBYTES_MAX, do: :erlang.exit(:salty_nif_not_loaded)
  def generichash_blake2b_KEYBYTES, do: :erlang.exit(:salty_nif_not_loaded)
  def generichash_blake2b_SALTBYTES, do: :erlang.exit(:salty_nif_not_loaded)
  def generichash_blake2b_PERSONALBYTES, do: :erlang.exit(:salty_nif_not_loaded)
  def generichash_blake2b(_,_,_), do: :erlang.exit(:salty_nif_not_loaded)
  def generichash_blake2b_salt_personal(_,_,_,_,_), do: :erlang.exit(:salty_nif_not_loaded)
  def generichash_blake2b_init(_,_), do: :erlang.exit(:salty_nif_not_loaded)
  def generichash_blake2b_init_salt_personal(_,_,_,_), do: :erlang.exit(:salty_nif_not_loaded)
  def generichash_blake2b_update(_,_), do: :erlang.exit(:salty_nif_not_loaded)
  def generichash_blake2b_final(_,_), do: :erlang.exit(:salty_nif_not_loaded)

  def hash_sha256_BYTES, do: :erlang.exit(:salty_nif_not_loaded)
  def hash_sha256(_), do: :erlang.exit(:salty_nif_not_loaded)
  def hash_sha256_verify(_,_), do: :erlang.exit(:salty_nif_not_loaded)
  def hash_sha256_init(), do: :erlang.exit(:salty_nif_not_loaded)
  def hash_sha256_update(_,_), do: :erlang.exit(:salty_nif_not_loaded)
  def hash_sha256_final(_), do: :erlang.exit(:salty_nif_not_loaded)
  def hash_sha256_final_verify(_,_), do: :erlang.exit(:salty_nif_not_loaded)

  def hash_sha512_BYTES, do: :erlang.exit(:salty_nif_not_loaded)
  def hash_sha512(_), do: :erlang.exit(:salty_nif_not_loaded)
  def hash_sha512_verify(_,_), do: :erlang.exit(:salty_nif_not_loaded)
  def hash_sha512_init(), do: :erlang.exit(:salty_nif_not_loaded)
  def hash_sha512_update(_,_), do: :erlang.exit(:salty_nif_not_loaded)
  def hash_sha512_final(_), do: :erlang.exit(:salty_nif_not_loaded)
  def hash_sha512_final_verify(_,_), do: :erlang.exit(:salty_nif_not_loaded)

  def randombytes_SEEDBYTES(), do: :erlang.exit(:salty_nif_not_loaded)
  def randombytes_random(), do: :erlang.exit(:salty_nif_not_loaded)
  def randombytes_stir(), do: :erlang.exit(:salty_nif_not_loaded)
  def randombytes_uniform(_), do: :erlang.exit(:salty_nif_not_loaded)
  def randombytes_buf(_), do: :erlang.exit(:salty_nif_not_loaded)
  def randombytes_buf_deterministic(_,_), do: :erlang.exit(:salty_nif_not_loaded)
  def randombytes_close(), do: :erlang.exit(:salty_nif_not_loaded)
end
