defmodule Salty.Supervisor do
  @moduledoc """
  Salty.Supervisor is the root supervisor of GenServer processes in libsalty.
  """

  use Supervisor

  def start_link do
    Supervisor.start_link(__MODULE__, [])
  end

  def init([]) do
    children = [
      # worker(Salty.Server, [], restart: :transient)
    ]

    supervise(children, strategy: :one_for_one)
  end
end
