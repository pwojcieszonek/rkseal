# frozen_string_literal: true

module RKSeal
  module Commands
    # Immutable value object describing the outcome of a command flow, returned
    # to the CLI so it can print a result without reaching into flow internals.
    #
    # Shared by {RKSeal::Commands::Create} and {RKSeal::Commands::Edit}; it lives
    # in its own file so neither command file owns the other's return type.
    #
    # @!attribute [r] secret_name
    #   @return [String] the Secret name that was sealed.
    # @!attribute [r] namespace
    #   @return [String] the namespace it was sealed for.
    # @!attribute [r] output_path
    #   @return [String] absolute path of the written `<name>.yaml`.
    # @!attribute [r] deployed
    #   @return [Boolean] whether the manifest was applied to the cluster
    #     (always false for `create`).
    Result = Data.define(:secret_name, :namespace, :output_path, :deployed)
  end
end
