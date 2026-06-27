# frozen_string_literal: true

module RKSeal
  module Commands
    # Orchestrates the `rkseal create <namespace> <secret-name>` flow.
    #
    # Pulls together the collaborators (workspace, editor, kubeseal, secret
    # model) to: seed an empty Secret template, optionally pre-seed
    # `--from-file` values, edit it in `$EDITOR` on a RAM-backed buffer, parse
    # and validate the result, seal it, and write `<secret-name>.yaml` to the
    # current working directory. Holds no business rules of its own beyond
    # sequencing -- each step's logic lives in the collaborator it delegates to.
    #
    # Collaborators are injected (defaulting to real implementations) so the
    # whole flow is unit-testable with stubbed adapters and no cluster.
    #
    # @example
    #   RKSeal::Commands::Create.new(namespace: "app", name: "db", scope: :strict).call
    class Create
      # @return [String]
      attr_reader :namespace
      # @return [String]
      attr_reader :name
      # @return [Symbol] sealing scope (:strict, :namespace_wide, :cluster_wide).
      attr_reader :scope

      # @param namespace [String] target namespace (positional CLI arg).
      # @param name [String] Secret name (positional CLI arg).
      # @param scope [Symbol] sealing scope; defaults to :strict.
      # @param type [String] Secret type for the seed (e.g. "kubernetes.io/tls").
      # @param from_file [Hash{String=>String}, nil] optional key => file-path
      #   pairs to pre-seed into the buffer before editing.
      # @param no_edit [Boolean] skip the editor and seal the seeded/from-file
      #   Secret directly (for binary/TLS/dockerconfig payloads).
      # @param string_data [Boolean] seed an empty `stringData` (plaintext) block
      #   instead of `data` (base64); defaults to false.
      # @param kubeseal [RKSeal::Kubeseal] sealing adapter.
      # @param editor [RKSeal::Editor] editor launcher.
      # @param workspace [#with] RAM-backed scratch provider (block-scoped).
      # @param output_dir [String] directory the manifest is written to (CWD).
      def initialize(namespace:, name:, scope: :strict, type: Secret::DEFAULT_TYPE,
                     from_file: nil, no_edit: false, string_data: false,
                     kubeseal: Kubeseal.new, editor: Editor.new,
                     workspace: SecureWorkspace, output_dir: Dir.pwd)
        @namespace = namespace
        @name = name
        @scope = scope
        @type = type
        @from_file = from_file || {}
        @no_edit = no_edit
        @string_data = string_data
        @kubeseal = kubeseal
        @editor = editor
        @workspace = workspace
        @output_dir = output_dir
      end

      # Run the create flow end to end.
      #
      # Side effects: spawns `$EDITOR` (unless --no-edit); provisions and tears
      # down a RAM-backed workspace; shells out to `kubeseal`; writes
      # `<name>.yaml` into the output directory.
      #
      # @return [RKSeal::Commands::Result] outcome (written path, deployed: false).
      # @raise [RKSeal::InvalidInputError] empty/malformed buffer, bad scope, or
      #   missing `--from-file` source.
      # @raise [RKSeal::EditorError] editor unavailable or aborted.
      # @raise [RKSeal::WorkspaceError] RAM-backed scratch could not be provided.
      # @raise [RKSeal::CommandError] kubeseal failed, or the controller is
      #   unreachable with no offline cert (surfaced up front, before editing).
      def call
        @kubeseal.ensure_available!
        # Resolve the cert before the editor/workspace open: an unreachable
        # controller (and no offline cert) must fail fast, not after the user has
        # spent time editing a buffer that can never be sealed.
        @kubeseal.ensure_cert!

        secret = preseeded_secret
        secret = edit(secret) unless @no_edit
        secret.validate!

        path = write_manifest(@kubeseal.seal(secret.to_manifest(scope: @scope), scope: @scope))
        Result.new(secret_name: @name, namespace: @namespace, output_path: path, deployed: false)
      end

      private

      # Seed an empty Secret and fold every `--from-file` value into it. Reading
      # the file lives here (not in the adapter or model): the model stays pure,
      # and a missing path fails fast with an actionable message.
      def preseeded_secret
        @from_file.reduce(Secret.seed(name: @name, namespace: @namespace,
                                      type: @type)) do |secret, (key, path)|
          secret.with_value(key: key, contents: read_source(key, path))
        end
      end

      def read_source(key, path)
        File.binread(path)
      rescue SystemCallError => e
        raise InvalidInputError, "--from-file #{key}=#{path}: #{e.message}"
      end

      # Run the editor on the seed buffer inside the RAM-backed workspace so the
      # plaintext never lands on persistent disk, then parse the saved buffer.
      def edit(secret)
        edited = @workspace.with(basename: @name) do |path|
          @editor.edit(content: secret.to_buffer(commented: true, string_data: @string_data),
                       path: path)
        end
        Secret.from_buffer(edited)
      end

      def write_manifest(sealed_yaml)
        path = File.join(@output_dir, "#{@name}.yaml")
        File.write(path, sealed_yaml)
        File.expand_path(path)
      end
    end
  end
end
