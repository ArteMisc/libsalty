defmodule Salty.Mixfile do
  use Mix.Project

  @github "https://github.com/ArteMisc/libsalty"

  def project do
    [
      app: :salty,
      version: "0.1.0",
      elixir: "~> 1.4",
      build_embedded: Mix.env == :prod,
      start_permanent: Mix.env == :prod,
      aliases: aliases(),
      description: description(),
      package: package(),
      deps: deps(),
      docs: [readme: true, main: "README.md"],
      source_url: @github
    ]
  end

  # Configuration for the OTP application
  def application do
    [mod: {Salty.Application, []}]
  end

  defp aliases do
    [compile: ["compile", &make/1]]
  end

  defp deps do
    []
  end

  defp make(_) do
    IO.puts "compiling salty_nif bindings"
    unless Mix.shell.cmd("make") === 0 do
      raise Mix.Error, message: "make encountered an error"
    end
    IO.puts "compiling salty_nif bindings done"
  end

  defp description do
    """
    An Elixir wrapper around the libsodium cryptographic library.
    Based on erlang-nif.
    """
  end

  defp package do
    [
      name: "libsalty",
      files: ["config", "src", "lib", "mix.exs", "Makefile", "LICENSE*", "README*"],
      maintainers: ["jan@artemisc.eu"],
      licenses: ["Apacha License, Version 2.0"],
      links: %{"Github" => @github}
    ]
  end
end
