# frozen_string_literal: true

require "thor"

module RKSeal
  module Commands
    # Orchestrates the `rkseal edit <namespace> <secret-name>` flow.
    #
    # Recovers the *current* state from the live cluster Secret (the only source
    # of truth -- a SealedSecret cannot be decrypted client-side), shows it in
    # `$EDITOR` on a RAM-backed buffer with `data` kept as base64, re-seals, and
    # writes `<secret-name>.yaml` to the current working directory.
    #
    # Three behaviours distinguish this flow:
    #   - **scope preservation:** the existing SealedSecret's scope is read from
    #     the cluster (annotation), falling back to the local `<name>.yaml`, then
    #     to :strict. An explicit `scope:` always overrides.
    #   - **no-op:** if the saved buffer is equivalent to the cluster Secret,
    #     nothing is written and no fresh ciphertext is produced (re-sealing
    #     identical input still yields new ciphertext, which would create spurious
    #     diffs); the flow exits cleanly with a "no changes" Result -- and, since
    #     there is nothing new to apply, a requested deploy is skipped too.
    #   - **deploy:** opt-in only. When requested, {RKSeal::ContextGuard} surfaces
    #     the active context and asks the operator to confirm before
    #     `kubectl apply` (unless `assume_yes`). If the Secret is absent from the
    #     cluster, the flow fails fast and points the user at `create`.
    #
    # Collaborators are injected so the flow is unit-testable without a cluster.
    #
    # @example write-only (default)
    #   RKSeal::Commands::Edit.new(namespace: "app", name: "db").call
    # @example deploy after editing (explicit opt-in)
    #   RKSeal::Commands::Edit.new(namespace: "app", name: "db", deploy: true).call
    class Edit
      # @return [String]
      attr_reader :namespace
      # @return [String]
      attr_reader :name
      # @return [Symbol, nil] explicit sealing scope override, or nil to preserve
      #   the secret's existing scope.
      attr_reader :scope
      # @return [Boolean] whether to deploy after writing the manifest.
      attr_reader :deploy

      # @param namespace [String] target namespace (positional CLI arg).
      # @param name [String] Secret name (positional CLI arg).
      # @param scope [Symbol, nil] explicit scope override; nil preserves the
      #   secret's existing scope (read from cluster / local file, else :strict).
      # @param deploy [Boolean] opt-in deploy after writing; defaults to false.
      # @param assume_yes [Boolean] skip the interactive deploy confirmation
      #   (only meaningful with deploy:); for non-interactive pipelines.
      # @param string_data [Boolean] present values as decoded plaintext
      #   `stringData` instead of base64 `data`; defaults to false (an opt-in
      #   plaintext exposure of the cluster Secret).
      # @param kubectl [RKSeal::Kubectl] cluster adapter (read + apply).
      # @param kubeseal [RKSeal::Kubeseal] sealing adapter.
      # @param editor [RKSeal::Editor] editor launcher.
      # @param context_guard [RKSeal::ContextGuard, nil] deploy gatekeeper; built
      #   from the kubectl adapter + prompt when nil and a deploy is requested.
      # @param prompt [Thor::Shell::Basic] shell used for the deploy confirmation
      #   (passed to the ContextGuard when one is built here).
      # @param workspace [#with] RAM-backed scratch provider (block-scoped).
      # @param output_dir [String] directory the manifest is written to (CWD).
      def initialize(namespace:, name:, scope: nil, deploy: false, assume_yes: false,
                     string_data: false,
                     kubectl: Kubectl.new, kubeseal: Kubeseal.new, editor: Editor.new,
                     context_guard: nil, prompt: Thor::Shell::Basic.new,
                     workspace: SecureWorkspace, output_dir: Dir.pwd)
        @namespace = namespace
        @name = name
        @scope = scope
        @deploy = deploy
        @assume_yes = assume_yes
        @string_data = string_data
        @kubectl = kubectl
        @kubeseal = kubeseal
        @editor = editor
        @context_guard = context_guard
        @prompt = prompt
        @workspace = workspace
        @output_dir = output_dir
      end

      # Run the edit flow end to end.
      #
      # Side effects: reads the cluster Secret (and SealedSecret scope) via
      # `kubectl`; spawns `$EDITOR`; provisions/tears down a RAM-backed workspace;
      # shells out to `kubeseal`; writes `<name>.yaml` (unless unchanged); and,
      # only when {#deploy} is true and the operator confirms, runs `kubectl
      # apply`.
      #
      # @return [RKSeal::Commands::Result] outcome (written path or nil when
      #   unchanged, deployed?).
      # @raise [RKSeal::NotFoundError] the Secret is absent from the cluster.
      # @raise [RKSeal::InvalidInputError] empty/malformed buffer, or bad scope.
      # @raise [RKSeal::EditorError] editor unavailable or aborted.
      # @raise [RKSeal::WorkspaceError] RAM-backed scratch could not be provided.
      # @raise [RKSeal::CommandError] kubectl/kubeseal failed.
      def call
        ensure_dependencies!

        cluster_secret = Secret.from_kubectl_json(@kubectl.get_secret(name: @name,
                                                                      namespace: @namespace))
        edited = edit(cluster_secret)

        return unchanged_result if edited == cluster_secret

        edited.validate!
        effective_scope = @scope || resolve_scope
        path = write_manifest(@kubeseal.seal(edited.to_manifest(scope: effective_scope),
                                             scope: effective_scope))
        deployed = @deploy && deploy_confirmed?
        @kubectl.apply(file: path) if deployed
        Result.new(secret_name: @name, namespace: @namespace, output_path: path, deployed: deployed)
      end

      private

      def ensure_dependencies!
        @kubectl.ensure_available!
        @kubeseal.ensure_available!
      end

      # Determine the scope to seal with when no explicit override was given:
      # preserve the secret's existing scope. Source of truth is the cluster
      # SealedSecret's annotation; if it is unreachable or absent, fall back to
      # the local `<name>.yaml` from a previous run; if neither, default :strict.
      def resolve_scope
        scope_from_cluster || scope_from_local_file || :strict
      end

      def scope_from_cluster
        Secret.scope_from_sealed_json(@kubectl.get_sealedsecret(name: @name, namespace: @namespace))
      rescue NotFoundError, CommandError
        nil
      end

      def scope_from_local_file
        path = manifest_path
        return nil unless File.file?(path)

        Secret.scope_from_sealed_json(File.read(path))
      end

      # Show the cluster Secret (base64 data) in the editor on a RAM-backed path,
      # then parse the saved buffer back into a Secret.
      def edit(cluster_secret)
        buffer = cluster_secret.to_buffer(commented: true, string_data: @string_data)
        edited = @workspace.with(basename: @name) do |path|
          @editor.edit(content: buffer, path: path)
        end
        Secret.from_buffer(edited)
      end

      # Nothing changed: per the no-op contract we write no file and produce no
      # fresh ciphertext. output_path is nil so the CLI can print "no changes".
      def unchanged_result
        Result.new(secret_name: @name, namespace: @namespace, output_path: nil, deployed: false)
      end

      def write_manifest(sealed_yaml)
        File.write(manifest_path, sealed_yaml)
        File.expand_path(manifest_path)
      end

      def manifest_path
        File.join(@output_dir, "#{@name}.yaml")
      end

      # Whether to proceed with the deploy: --yes skips the prompt outright,
      # otherwise the ContextGuard surfaces the active context and confirms.
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
