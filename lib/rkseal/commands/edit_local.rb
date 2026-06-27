# frozen_string_literal: true

require "thor"
require "yaml"
require "base64"

module RKSeal
  module Commands
    # Orchestrates the offline `rkseal edit --local <namespace> <secret-name>`
    # flow: edit a SealedSecret that exists only as a local `<name>.yaml` and was
    # never deployed, so there is no unsealed cluster Secret to recover values
    # from.
    #
    # A SealedSecret cannot be decrypted client-side, so this flow never shows
    # current values. Instead {RKSeal::SealedSecret} renders a *redacted* buffer
    # (every existing key shown as {RKSeal::SealedSecret::REDACTED_PLACEHOLDER}),
    # and the saved buffer is classified per key:
    #
    #   - **keep:** value left as the placeholder -> the existing ciphertext is
    #     left byte-for-byte untouched (no rehash, no plaintext needed);
    #   - **reseal:** value replaced, or a brand-new key added -> the new value
    #     is sealed and merged in via `kubeseal --merge-into`;
    #   - **remove:** an existing key deleted from the buffer -> dropped from
    #     `spec.encryptedData`.
    #
    # The `type` may also be edited (written to `spec.template.type`). Scope and
    # name/namespace are fixed: kept ciphertext cannot be re-sealed under a
    # different scope/identity without the plaintext rkseal does not have.
    #
    # The cluster is contacted only to obtain the controller's PUBLIC cert when a
    # reseal is actually needed (offline if it is already cached) and, with an
    # opt-in `--deploy`, to apply the result. Reading current state never hits
    # the cluster.
    #
    # @example keep/replace/add keys offline, write only
    #   RKSeal::Commands::EditLocal.new(namespace: "app", name: "db").call
    #
    # rubocop:disable Metrics/ClassLength -- this flow is a single cohesive
    # orchestration (read local -> redacted buffer -> classify keep/reseal/
    # remove -> merge/rewrite -> optional deploy); the extra lines are docstrings
    # and small, focused private helpers, each independently testable. Splitting
    # it into verb classes is the anti-pattern this gem avoids.
    class EditLocal
      # @return [String]
      attr_reader :namespace
      # @return [String]
      attr_reader :name
      # @return [Boolean] whether to deploy after writing the manifest.
      attr_reader :deploy

      # @param namespace [String] target namespace (positional CLI arg).
      # @param name [String] Secret name (positional CLI arg).
      # @param deploy [Boolean] opt-in deploy after writing; defaults to false.
      # @param assume_yes [Boolean] skip the deploy confirmation (with deploy:).
      # @param string_data [Boolean] show the redacted keys under `stringData`
      #   (plaintext) instead of `data` (base64); defaults to false.
      # @param kubectl [RKSeal::Kubectl] cluster adapter (apply only).
      # @param kubeseal [RKSeal::Kubeseal] sealing adapter (merge_into).
      # @param editor [RKSeal::Editor] editor launcher.
      # @param context_guard [RKSeal::ContextGuard, nil] deploy gatekeeper.
      # @param prompt [Thor::Shell::Basic] shell for the deploy confirmation.
      # @param workspace [#with] RAM-backed scratch provider (block-scoped).
      # @param output_dir [String] directory the manifest is read from / written
      #   to (CWD).
      def initialize(namespace:, name:, deploy: false, assume_yes: false, string_data: false,
                     kubectl: Kubectl.new, kubeseal: Kubeseal.new, editor: Editor.new,
                     context_guard: nil, prompt: Thor::Shell::Basic.new,
                     workspace: SecureWorkspace, output_dir: Dir.pwd)
        @namespace = namespace
        @name = name
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

      # Run the local edit flow end to end.
      #
      # @return [RKSeal::Commands::Result] outcome (written path or nil when
      #   unchanged, deployed?).
      # @raise [RKSeal::NotFoundError] no local `<name>.yaml` (points at `create`).
      # @raise [RKSeal::InvalidInputError] malformed/empty buffer, renamed
      #   identity, empty result, or a new key left as the placeholder.
      # @raise [RKSeal::EditorError] editor unavailable or aborted.
      # @raise [RKSeal::WorkspaceError] RAM-backed scratch could not be provided.
      # @raise [RKSeal::CommandError] kubeseal/kubectl failed.
      def call
        @kubeseal.ensure_available!
        @kubectl.ensure_available! if @deploy

        sealed = SealedSecret.parse(read_local!)
        plan = build_plan(sealed, edit(sealed))
        return unchanged_result unless plan.changes?

        ensure_nonempty!(sealed, plan)
        apply(plan, scope: sealed.scope)

        path = File.expand_path(manifest_path)
        deployed = @deploy && deploy_confirmed?
        @kubectl.apply(file: path) if deployed
        Result.new(secret_name: @name, namespace: @namespace, output_path: path, deployed: deployed)
      end

      # The classified result of one local-edit buffer: which keys to reseal
      # (from plaintext stringData or verbatim base64 data), which to remove, and
      # whether the template type changed. Kept keys are absent by construction.
      LocalPlan = Struct.new(
        :reseal_string_data, :reseal_data, :removed_keys, :type, :type_changed,
        keyword_init: true
      ) do
        # @return [Boolean] whether any key must be (re)sealed.
        def reseal?
          !reseal_string_data.empty? || !reseal_data.empty?
        end

        # @return [Boolean] whether the buffer changed anything at all.
        def changes?
          reseal? || removed_keys.any? || type_changed
        end
      end

      private

      # The local SealedSecret is the only source: this flow is offline by
      # design and never reads cluster state. A missing file points at `create`.
      def read_local!
        path = manifest_path
        return File.read(path) if File.file?(path)

        raise NotFoundError,
              "No local #{@name}.yaml in #{@output_dir}. " \
              "Run `rkseal create #{@namespace} #{@name}` first " \
              "(local edit operates on the SealedSecret file, not the cluster)."
      end

      # Show the redacted buffer on a RAM-backed path, then parse the saved
      # buffer into raw stringData/data maps and the chosen type.
      def edit(sealed)
        raw = @workspace.with(basename: @name) do |path|
          @editor.edit(content: sealed.to_buffer(commented: true, string_data: @string_data),
                       path: path)
        end
        parse_buffer(raw)
      end

      def parse_buffer(raw)
        raise InvalidInputError, "the edit buffer is empty" if raw.nil? || raw.strip.empty?

        doc = YAML.safe_load(raw, permitted_classes: [], aliases: false)
        unless doc.is_a?(Hash)
          raise InvalidInputError,
                "the buffer is not a YAML mapping (expected a Secret manifest)"
        end

        validate_identity!(doc)
        {
          string_data: string_map(doc["stringData"]),
          data: string_map(doc["data"]),
          type: doc["type"] || Secret::DEFAULT_TYPE
        }
      rescue Psych::SyntaxError => e
        raise InvalidInputError, "the buffer is not valid YAML: #{e.message}"
      end

      # name/namespace are bound into strict ciphertext and shared with kept
      # entries, so they cannot change in a local edit.
      def validate_identity!(doc)
        name = doc.dig("metadata", "name")
        namespace = doc.dig("metadata", "namespace")
        return if name == @name && namespace == @namespace

        raise InvalidInputError,
              "local edit cannot rename or move the secret " \
              "(expected #{@name}/#{@namespace}, got #{name.inspect}/#{namespace.inspect})"
      end

      def string_map(raw)
        return {} if raw.nil?
        raise InvalidInputError, "`stringData`/`data` must be a mapping" unless raw.is_a?(Hash)

        raw.transform_keys(&:to_s)
      end

      # Classify the saved buffer against the existing keys into a {LocalPlan}.
      # Keys may sit under `stringData` (plaintext) or `data` (base64) regardless
      # of which block the redacted buffer used, so both are classified the same
      # way; the redacted placeholder is honoured in either.
      def build_plan(sealed, buffer)
        existing = sealed.encrypted_keys
        reseal_string = reseal_values(buffer[:string_data], existing)
        reseal_data = reseal_values(buffer[:data], existing)
        present = buffer[:string_data].keys + buffer[:data].keys

        LocalPlan.new(
          reseal_string_data: reseal_string,
          reseal_data: reseal_data,
          removed_keys: existing - present,
          type: buffer[:type],
          type_changed: buffer[:type] != sealed.type
        )
      end

      # Keys whose value is NOT the redacted placeholder are (re)seals; a
      # placeholder on an existing key is kept (dropped here). A placeholder left
      # on a brand-new key is meaningless -> fail fast.
      def reseal_values(map, existing)
        map.each_with_object({}) do |(key, value), acc|
          if value == SealedSecret::REDACTED_PLACEHOLDER
            next if existing.include?(key)

            raise InvalidInputError,
                  "new key #{key.inspect} still has the #{SealedSecret::REDACTED_PLACEHOLDER} " \
                  "placeholder; give it a value or remove the line"
          end
          raise InvalidInputError, "key #{key.inspect} has an empty value" if blank?(value)

          acc[key] = value
        end
      end

      # The final key set must not be empty (a Secret with no data is invalid).
      def ensure_nonempty!(sealed, plan)
        remaining = (sealed.encrypted_keys - plan.removed_keys) +
                    plan.reseal_string_data.keys + plan.reseal_data.keys
        return unless remaining.uniq.empty?

        raise InvalidInputError, "the edit would leave the SealedSecret with no data items"
      end

      # Apply the plan to `<name>.yaml`: merge resealed items via kubeseal, then
      # always normalize the file -- drop removed keys, update the template type,
      # and re-emit YAML. The normalize pass is unconditional because
      # `kubeseal --merge-into` (v0.36.6) rewrites the file as JSON regardless of
      # the input format, so a `.yaml` would otherwise be left holding JSON.
      def apply(plan, scope:)
        path = manifest_path
        if plan.reseal?
          @kubeseal.ensure_cert!
          @kubeseal.merge_into(reseal_secret(plan).to_manifest(scope: scope), file: path,
                                                                              scope: scope)
        end
        normalize_file(path, plan)
      end

      # Build the partial Secret carrying only the (re)sealed items. Round-tripped
      # through {RKSeal::Secret.from_buffer} to reuse its base64 validation and
      # stringData folding (stringData wins per key, exactly like a normal seal).
      def reseal_secret(plan)
        manifest = {
          "apiVersion" => Secret::API_VERSION,
          "kind" => Secret::KIND,
          "metadata" => { "name" => @name, "namespace" => @namespace },
          "type" => plan.type
        }
        manifest["stringData"] = plan.reseal_string_data unless plan.reseal_string_data.empty?
        manifest["data"] = plan.reseal_data unless plan.reseal_data.empty?
        Secret.from_buffer(YAML.dump(manifest))
      end

      # Re-read the SealedSecret kubeseal just wrote (JSON or YAML -- YAML parses
      # both), apply the removals and the optional type change, and write it back
      # as YAML so a `.yaml` always holds YAML.
      def normalize_file(path, plan)
        doc = YAML.safe_load_file(path, permitted_classes: [], aliases: false)
        spec = doc["spec"] ||= {}
        encrypted = spec["encryptedData"] ||= {}
        plan.removed_keys.each { |key| encrypted.delete(key) }
        (spec["template"] ||= {})["type"] = plan.type if plan.type_changed
        File.write(path, YAML.dump(doc))
      end

      def unchanged_result
        Result.new(secret_name: @name, namespace: @namespace, output_path: nil, deployed: false)
      end

      def manifest_path
        File.join(@output_dir, "#{@name}.yaml")
      end

      def deploy_confirmed?
        return true if @assume_yes

        context_guard.confirm_deploy(secret_name: @name, namespace: @namespace)
      end

      def context_guard
        @context_guard ||= ContextGuard.new(kubectl: @kubectl, prompt: @prompt)
      end

      def blank?(value)
        value.nil? || (value.respond_to?(:strip) && value.to_s.strip.empty?)
      end
    end
    # rubocop:enable Metrics/ClassLength
  end
end
