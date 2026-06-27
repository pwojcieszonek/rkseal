# frozen_string_literal: true

module RKSeal
  module Commands
    # Orchestrates the `rkseal view <namespace> <secret-name>` flow.
    #
    # A strictly read-only inspector: it reads the live unsealed Secret from the
    # cluster (the only source of current values) and renders the full Secret
    # manifest as a string for the CLI to print. It NEVER opens `$EDITOR`, never
    # provisions a {RKSeal::SecureWorkspace}, and never writes a file.
    #
    # By default `data` is shown as raw base64 (verbatim, consistent with `edit`).
    # With `reveal: true` the values are decoded and presented as plaintext
    # `stringData` -- an explicit opt-in for the operator who wants to read the
    # cleartext.
    #
    # If the Secret is absent from the cluster, the flow fails fast and points the
    # user at `create`.
    #
    # @example show base64 (default)
    #   puts RKSeal::Commands::View.new(namespace: "app", name: "db").call
    # @example reveal plaintext
    #   puts RKSeal::Commands::View.new(namespace: "app", name: "db", reveal: true).call
    class View
      # @return [String]
      attr_reader :namespace
      # @return [String]
      attr_reader :name
      # @return [Boolean] whether to decode data to plaintext stringData.
      attr_reader :reveal

      # @param namespace [String] target namespace (positional CLI arg).
      # @param name [String] Secret name (positional CLI arg).
      # @param reveal [Boolean] decode data to plaintext; defaults to false.
      # @param kubectl [RKSeal::Kubectl] cluster adapter (read only).
      def initialize(namespace:, name:, reveal: false, kubectl: Kubectl.new)
        @namespace = namespace
        @name = name
        @reveal = reveal
        @kubectl = kubectl
      end

      # Run the view flow: read the cluster Secret and render it.
      #
      # Side effects: a single read-only `kubectl get secret`. No editor, no
      # workspace, no file write.
      #
      # @return [String] the full Secret manifest YAML to print.
      # @raise [RKSeal::NotFoundError] the Secret is absent (points at `create`).
      # @raise [RKSeal::CommandError] kubectl failed.
      def call
        @kubectl.ensure_available!
        secret = Secret.from_kubectl_json(@kubectl.get_secret(name: @name, namespace: @namespace))
        secret.to_buffer(reveal: @reveal)
      end
    end
  end
end
