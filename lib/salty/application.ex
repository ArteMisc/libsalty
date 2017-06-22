defmodule Salty.Application do
  @moduledoc """
  Salty.Application starts the application's root supervisor, and initializes
  the Nif bindings/sodium library.
  """

  use Application
  alias Salty.Nif, as: Nif

  def start(_type, _args) do
    :ok = Nif.load_nif()
    :ok = Nif.init()
    # TODO start the supervisor for GenServers that handle IO bound tasks
    Salty.Supervisor.start_link
  end

end
