defmodule Salty.Mixfile do
  use Mix.Project

  def project do
    [app: :salty,
     version: "0.1.0",
     elixir: "~> 1.4",
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     deps: []]
  end

  # Configuration for the OTP application
  def application do
    [extra_applications: [:logger],
     mod: {Salty.Application, []}]
  end
end
