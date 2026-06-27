# frozen_string_literal: true

require "thor"

module RKSeal
  module Commands
    # Orchestrates the `rkseal reencrypt <namespace> <secret-name>` flow.
    #
    # Re-encrypts an existing SealedSecret onto the controller's newest sealing
    # key without ever exposing plaintext (`kubeseal --re-encrypt`). The input is
    # the SealedSecret itself, not the unsealed Secret -- so unlike `edit`, this
    # flow never touches `$EDITOR`, a RAM workspace, or cluster Secret values.
    #
    # Input resolution, in order:
    #   1. the local `<name>.yaml` in the output directory (a previous run);
    #   2. otherwise the live SealedSecret via {RKSeal::Kubectl#get_sealedsecret}.
    # If neither exists, fail fast and point the user at `create`.
    #
    # Deploy is opt-in and identical to `edit`: {RKSeal::ContextGuard} surfaces
    # the active context and confirms before `kubectl apply` (skipped with
    # `assume_yes`).
    #
    # @example refresh to the newest key, write only
    #   RKSeal::Commands::Reencrypt.new(namespace: "app", name: "db").call
    class Reencrypt
      # @return [String]
      attr_reader :namespace
      # @return [String]
      attr_reader :name
      # @return [Boolean]
      attr_reader :deploy

      # @param namespace [String] target namespace (positional CLI arg).
      # @param name [String] Secret name (positional CLI arg).
      # @param deploy [Boolean] opt-in deploy after writing; defaults to false.
      # @param assume_yes [Boolean] skip the deploy confirmation (with deploy:).
      # @param kubectl [RKSeal::Kubectl] cluster adapter (read + apply).
      # @param kubeseal [RKSeal::Kubeseal] sealing adapter (re-encrypt).
      # @param context_guard [RKSeal::ContextGuard, nil] deploy gatekeeper; built
      #   from kubectl + prompt when nil and a deploy is requested.
      # @param prompt [Thor::Shell::Basic] shell for the deploy confirmation.
      # @param output_dir [String] directory the manifest is read from / written
      #   to (CWD).
      def initialize(namespace:, name:, deploy: false, assume_yes: false,
                     kubectl: Kubectl.new, kubeseal: Kubeseal.new,
                     context_guard: nil, prompt: Thor::Shell::Basic.new,
                     output_dir: Dir.pwd)
        @namespace = namespace
        @name = name
        @deploy = deploy
        @assume_yes = assume_yes
        @kubectl = kubectl
        @kubeseal = kubeseal
        @context_guard = context_guard
        @prompt = prompt
        @output_dir = output_dir
      end

      # Run the re-encrypt flow end to end.
      #
      # Side effects: reads the local `<name>.yaml` or the cluster SealedSecret;
      # shells out to `kubeseal --re-encrypt`; writes `<name>.yaml`; and, only
      # when {#deploy} is true and the operator confirms, runs `kubectl apply`.
      #
      # @return [RKSeal::Commands::Result] outcome (written path, deployed?).
      # @raise [RKSeal::NotFoundError] no local file and the SealedSecret is
      #   absent from the cluster (message points at `create`).
      # @raise [RKSeal::CommandError] kubectl/kubeseal failed.
      def call
        @kubectl.ensure_available!
        @kubeseal.ensure_available!

        reencrypted = @kubeseal.re_encrypt(source_sealed_yaml)
        path = write_manifest(reencrypted)
        deployed = @deploy && deploy_confirmed?
        @kubectl.apply(file: path) if deployed
        Result.new(secret_name: @name, namespace: @namespace, output_path: path, deployed: deployed)
      end

      private

      # The SealedSecret to re-encrypt: prefer the local file, fall back to the
      # cluster. A missing cluster SealedSecret surfaces as NotFoundError from the
      # adapter, which we re-message to point at `create`.
      def source_sealed_yaml
        local = manifest_path
        return File.read(local) if File.file?(local)

        @kubectl.get_sealedsecret(name: @name, namespace: @namespace)
      rescue NotFoundError
        raise NotFoundError,
              "No local #{@name}.yaml and no SealedSecret #{@name.inspect} in " \
              "namespace #{@namespace.inspect}. Run `rkseal create` first."
      end

      def write_manifest(sealed_yaml)
        File.write(manifest_path, sealed_yaml)
        File.expand_path(manifest_path)
      end

      def manifest_path
        File.join(@output_dir, "#{@name}.yaml")
      end

      # Whether to proceed with the deploy: --yes skips the prompt, otherwise the
      # ContextGuard surfaces the active context and confirms.
      def deploy_confirmed?
        return true if @assume_yes

        context_guard.confirm_deploy(secret_name: @name, namespace: @namespace)
      end

      def context_guard
        @context_guard ||= ContextGuard.new(kubectl: @kubectl, prompt: @prompt)
      end
    end
  end
end
