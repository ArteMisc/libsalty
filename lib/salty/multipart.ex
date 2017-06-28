defmodule Salty.Multipart do

  defmodule Spec do
    @callback update(binary(), binary()) :: {:ok, binary()} | {:error, atom()}
    @callback final(binary()) :: {:ok, binary()} | {:error, atom()}
    @callback final_verify(binary(), binary()) :: :ok | {:error, atom()}
  end

  defmodule SignSpec do
    @callback update(binary(), binary()) :: {:ok, binary()} | {:error, atom()}
    @callback final(binary(), binary()) :: {:ok, binary()} | {:error, atom()}
    @callback final_verify(binary(), binary(), binary()) :: :ok | {:error, atom()}
  end

  def init(spec) do
    init_return(spec, spec.init())
  end
  def init(spec, arg1) do
    init_return(spec, spec.init(arg1))
  end
  def init(spec, arg1, arg2) do
    init_return(spec, spec.init(arg1, arg2))
  end
  defp init_return(spec, result) do
    case result do
      {:ok, next} -> {:ok, {spec, next}}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """

  """
  def update({:ok, {spec, state}}, input) do
    update({spec, state}, input)
  end
  def update({:error, _} = err, _) do
    err
  end
  def update({spec, state}, input) do
    case spec.update(state, input) do
      {:ok, next} -> {:ok, {spec, next}}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """

  """
  def final({:ok, {spec, state}}) do
    final({spec, state})
  end
  def final({:error, _} = err) do
    err
  end
  def final({spec, state}) do
    spec.final(state)
  end

  @doc """

  """
  def final_verify({:ok, {spec, state}}, expected) do
    final_verify({spec, state}, expected)
  end
  def final_verify({:error, _} = err, _) do
    err
  end
  def final_verify({spec, state}, expected) do
    spec.final_verify(state, expected)
  end
end
