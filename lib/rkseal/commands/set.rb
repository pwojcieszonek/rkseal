# frozen_string_literal: true

require "thor"
require "yaml"
require "base64"

module RKSeal
  module Commands
    # Orchestrates the `rkseal set <namespace> <secret-name> <key>` flow: seal
    # ONE value into an existing SealedSecret without opening an editor.
    #
    # Built on the blind `kubeseal --merge-into`: the new value is sealed and
    # written under `key` (added, or replacing the existing entry) while every
    # other sealed entry stays byte-for-byte untouched, and nothing is ever
    # decrypted. So, unlike `edit`, this flow needs neither the cluster Secret
    # nor `$EDITOR` nor a RAM workspace -- the plaintext goes from the value
    # source straight to kubeseal's stdin.
    #
    # Input resolution mirrors `reencrypt`: the local `<name>.yaml` is the
    # working copy when present; otherwise the live SealedSecret is fetched
    # from the cluster, stripped of apiserver runtime metadata, and materialised
    # as the new local file (merge-into needs a file to merge into). If neither
    # exists, fail fast and point at `create`.
    #
    # Scope, template `type`, name and namespace come from the sourced
    # SealedSecret and cannot be changed here: `--merge-into` keeps the file's
    # template and identity whatever the partial Secret says, and the kept
    # ciphertext is bound to them anyway.
    #
    # The value is obtained lazily (`value_source.call`) only after the
    # SealedSecret is sourced and the controller cert is confirmed reachable, so
    # an interactive prompt is never shown for a run that would fail anyway.
    #
    # @example rotate one key from a plaintext value, write only
    #   RKSeal::Commands::Set.new(namespace: "app", name: "db", key: "password",
    #                             value_source: -> { "s3cret" }).call
    class Set
      # @return [String]
      attr_reader :namespace
      # @return [String]
      attr_reader :name
      # @return [String] the data key being set.
      attr_reader :key
      # @return [Boolean] whether to deploy after writing the manifest.
      attr_reader :deploy

      # @param namespace [String] target namespace (positional CLI arg).
      # @param name [String] Secret name (positional CLI arg).
      # @param key [String] data key to seal (already validated by the CLI).
      # @param value_source [#call] returns the raw value (String) on demand.
      # @param base64 [Boolean] the value is already base64 (validated, then
      #   stored canonically); defaults to false (plaintext, encoded here).
      # @param deploy [Boolean] opt-in deploy after writing; defaults to false.
      # @param assume_yes [Boolean] skip the deploy confirmation (with deploy:).
      # @param kubectl [RKSeal::Kubectl] cluster adapter (read SealedSecret + apply).
      # @param kubeseal [RKSeal::Kubeseal] sealing adapter (merge_into).
      # @param context_guard [RKSeal::ContextGuard, nil] deploy gatekeeper.
      # @param prompt [Thor::Shell::Basic] shell for the deploy confirmation.
      # @param output_dir [String] directory the manifest is read from / written
      #   to (CWD).
      def initialize(namespace:, name:, key:, value_source:, base64: false,
                     deploy: false, assume_yes: false,
                     kubectl: Kubectl.new, kubeseal: Kubeseal.new,
                     context_guard: nil, prompt: Thor::Shell::Basic.new,
                     output_dir: Dir.pwd)
        @namespace = namespace
        @name = name
        @key = key
        @value_source = value_source
        @base64 = base64
        @deploy = deploy
        @assume_yes = assume_yes
        @kubectl = kubectl
        @kubeseal = kubeseal
        @context_guard = context_guard
        @prompt = prompt
        @output_dir = output_dir
      end

      # Run the set flow end to end.
      #
      # Side effects: reads the local `<name>.yaml` or the cluster SealedSecret;
      # probes the controller cert; obtains the value; shells out to
      # `kubeseal --merge-into`; rewrites `<name>.yaml`; and, only when
      # {#deploy} is true and the operator confirms, runs `kubectl apply`.
      #
      # @return [RKSeal::Commands::Result] outcome (written path, deployed?).
      # @raise [RKSeal::NotFoundError] no local file and no cluster SealedSecret.
      # @raise [RKSeal::InvalidInputError] empty value, invalid base64 with
      #   `base64: true`, or a local file for a different secret.
      # @raise [RKSeal::CommandError] kubeseal/kubectl failed.
      def call
        @kubeseal.ensure_available!
        @kubectl.ensure_available! if @deploy
        merge_into_working_copy

        path = File.expand_path(manifest_path)
        deployed = @deploy && deploy_confirmed?
        @kubectl.apply(file: path) if deployed
        Result.new(secret_name: @name, namespace: @namespace, output_path: path, deployed: deployed)
      end

      private

      # The local `<name>.yaml` is the working copy. Without one, the cluster
      # object is materialised locally first -- and removed again unless the
      # merge completed, whatever interrupted it (kubeseal failure, Ctrl-C at
      # the prompt), so an operator never finds an unexplained `<name>.yaml`.
      def merge_into_working_copy
        return merge!(parse_local) if File.file?(manifest_path)

        @kubectl.ensure_available!
        sealed = materialise_from_cluster
        merged = false
        begin
          merge!(sealed)
          merged = true
        ensure
          File.delete(manifest_path) unless merged
        end
      end

      # `--merge-into` seals under the FILE's name/namespace regardless of what
      # the partial Secret says, so a working copy for another secret would
      # silently bind (and deploy) the value elsewhere.
      def parse_local
        sealed = SealedSecret.parse(File.read(manifest_path))
        return sealed if sealed.name == @name && sealed.namespace == @namespace

        raise InvalidInputError,
              "local #{@name}.yaml belongs to #{sealed.namespace}/#{sealed.name}, " \
              "not #{@namespace}/#{@name}"
      end

      # No local working copy: fetch the live SealedSecret and write it as
      # `<name>.yaml` so kubeseal has a file to merge into. A NotFound from the
      # cluster is re-messaged to point at `create`.
      def materialise_from_cluster
        doc = SealedSecret.strip_runtime(@kubectl.get_sealedsecret(name: @name,
                                                                   namespace: @namespace))
        sealed = SealedSecret.parse(doc)
        File.write(manifest_path, YAML.dump(doc))
        sealed
      rescue NotFoundError
        raise NotFoundError,
              "No local #{@name}.yaml and no SealedSecret #{@name.inspect} in " \
              "namespace #{@namespace.inspect}. " \
              "Run `rkseal create #{@namespace} #{@name}` first."
      end

      # Seal the one item and merge it into the local file.
      def merge!(sealed)
        @kubeseal.ensure_cert!
        partial = Secret.seed(name: @name, namespace: @namespace)
                        .with_value(key: @key, contents: plaintext_value)
        ensure_template_annotations! unless sealed.scope == :strict
        @kubeseal.merge_into(partial.to_manifest(scope: sealed.scope),
                             file: manifest_path, scope: sealed.scope)
      end

      # With a non-strict scope, `kubeseal --merge-into` writes the scope
      # annotation into `spec.template.metadata.annotations` and panics
      # (`assignment to entry in nil map`, seen on v0.36.6-v0.38.4) when that map
      # is absent. kubeseal-authored files carry it; hand-written or templated
      # ones often do not, so give it an empty map to write into.
      def ensure_template_annotations!
        doc = YAML.safe_load_file(manifest_path, permitted_classes: [], aliases: false)
        metadata = ((doc["spec"] ||= {})["template"] ||= {})["metadata"] ||= {}
        return if metadata["annotations"].is_a?(Hash)

        metadata["annotations"] = {}
        File.write(manifest_path, YAML.dump(doc))
      end

      # The plaintext bytes to seal. Emptiness is judged on the decoded value so
      # a whitespace-only `base64: true` input (which decodes to "") is rejected
      # like an empty plaintext one.
      def plaintext_value
        raw = @value_source.call.to_s
        value = @base64 ? decode_base64(raw) : raw
        raise InvalidInputError, "the value for key #{@key.inspect} is empty" if value.empty?

        value
      end

      # Whitespace is not part of the encoding: `base64`/`openssl base64` wrap
      # long output in lines, and a pipe adds a newline, so all of it is dropped
      # before the strict decode.
      def decode_base64(raw)
        Base64.strict_decode64(raw.gsub(/\s+/, ""))
      rescue ArgumentError
        raise InvalidInputError, "the value for key #{@key.inspect} is not valid base64"
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
    end
  end
end
