# frozen_string_literal: true

require "yaml"

module RKSeal
  # Domain model for the *SealedSecret* resource -- the encrypted, on-disk
  # counterpart of {RKSeal::Secret}.
  #
  # Unlike a Secret, a SealedSecret cannot be decrypted client-side: its
  # `spec.encryptedData` values are opaque ciphertext. What *is* readable is the
  # set of data **keys** (the map keys are plaintext), the sealing **scope**
  # (a metadata annotation), and the **template** `type`. That readable surface
  # is exactly what powers the offline `edit --local` flow: rkseal can show the
  # user which keys exist and let them keep / replace / add / remove keys
  # without ever seeing the current values.
  #
  # This model is the single place that knows how to:
  #
  #   - parse a local `<name>.yaml` SealedSecret into that readable surface;
  #   - render a *redacted* editor buffer -- a Secret manifest in which every
  #     existing key is shown under `stringData` as {REDACTED_PLACEHOLDER}, so a
  #     value left untouched means "keep the current ciphertext".
  #
  # No method here shells out, touches the cluster, or decrypts anything; it is
  # pure data transformation and trivially unit-testable.
  class SealedSecret
    # apiVersion/kind this model represents.
    API_VERSION = "bitnami.com/v1alpha1"
    KIND = "SealedSecret"

    # Placeholder shown for every existing key in the `edit --local` buffer.
    # Because the ciphertext cannot be decrypted, the current value is never
    # revealed; leaving this token in place means "keep the sealed value as-is".
    REDACTED_PLACEHOLDER = "<redacted>"

    # @return [String] the SealedSecret name.
    attr_reader :name
    # @return [String, nil] the namespace.
    attr_reader :namespace
    # @return [Symbol] sealing scope (:strict, :namespace_wide, :cluster_wide),
    #   derived from the metadata annotation (see {RKSeal::Secret.scope_from_sealed_json}).
    attr_reader :scope
    # @return [String] the template Secret `type` (e.g. "Opaque").
    attr_reader :type
    # @return [Array<String>] the data keys present in `spec.encryptedData`
    #   (plaintext keys; the values are ciphertext and are not held here).
    attr_reader :encrypted_keys

    class << self
      # Parse a SealedSecret manifest (the local `<name>.yaml`) into the model.
      #
      # @param yaml [String, Hash] raw YAML/JSON text or a pre-parsed Hash.
      # @return [RKSeal::SealedSecret]
      # @raise [RKSeal::InvalidInputError] if the document is empty, not valid
      #   YAML, not a SealedSecret, or carries a non-mapping `encryptedData`.
      def parse(yaml)
        doc = yaml.is_a?(Hash) ? yaml : load_yaml(yaml)
        unless doc.is_a?(Hash)
          raise InvalidInputError, "not a SealedSecret manifest (expected a YAML mapping)"
        end

        validate_kind!(doc)
        new(
          name: fetch_name(doc),
          namespace: doc.dig("metadata", "namespace"),
          scope: Secret.scope_from_sealed_json(doc),
          type: doc.dig("spec", "template", "type") || Secret::DEFAULT_TYPE,
          encrypted_keys: encrypted_keys(doc)
        )
      end

      # Whether the sealed payload (`spec.encryptedData` + `spec.template`) of two
      # SealedSecret documents differs. `kubectl apply` stores the manifest
      # verbatim, so right after a deploy the local `<name>.yaml` and the cluster
      # object share an identical payload; an unequal payload therefore means the
      # local file is *ahead of* (or absent from) the cluster -- i.e. it carries
      # un-deployed changes. Re-sealing is non-deterministic, so equal payload is
      # only ever produced by the exact same applied file -- there are no false
      # "equal" verdicts that could mask drift. Tolerant of JSON (kubectl) and
      # YAML (the local file) alike, and of malformed input (treated as drift, so
      # the user's local file is never silently overwritten).
      #
      # @param local [String, Hash] the local SealedSecret (YAML text or Hash).
      # @param cluster [String, Hash] the cluster SealedSecret (JSON/YAML or Hash).
      # @return [Boolean]
      def diverged?(local, cluster)
        sealed_payload(local) != sealed_payload(cluster)
      end

      private

      # The comparable sealed payload of a SealedSecret document: its
      # `encryptedData` and `template`. Anything unparseable collapses to a
      # sentinel that compares unequal to a real payload (so drift wins).
      def sealed_payload(document)
        doc = document.is_a?(Hash) ? document : safe_parse(document)
        spec = doc.is_a?(Hash) ? doc["spec"] : nil
        spec.is_a?(Hash) ? [spec["encryptedData"], spec["template"]] : [:unparseable]
      end

      # Best-effort parse for the divergence check: never raises, returns nil on
      # empty/invalid input (YAML.safe_load parses JSON too).
      def safe_parse(text)
        return nil if text.nil? || text.strip.empty?

        YAML.safe_load(text, permitted_classes: [], aliases: false)
      rescue Psych::SyntaxError
        nil
      end

      def load_yaml(text)
        raise InvalidInputError, "the SealedSecret file is empty" if text.nil? || text.strip.empty?

        YAML.safe_load(text, permitted_classes: [], aliases: false)
      rescue Psych::SyntaxError => e
        raise InvalidInputError, "the SealedSecret file is not valid YAML: #{e.message}"
      end

      def validate_kind!(doc)
        kind = doc["kind"]
        return if kind == KIND

        raise InvalidInputError, "not a SealedSecret (kind: #{kind.inspect})"
      end

      def fetch_name(doc)
        name = doc.dig("metadata", "name")
        return name unless name.nil? || (name.respond_to?(:strip) && name.strip.empty?)

        raise InvalidInputError, "the SealedSecret is missing metadata.name"
      end

      def encrypted_keys(doc)
        encrypted = doc.dig("spec", "encryptedData")
        return [] if encrypted.nil?
        unless encrypted.is_a?(Hash)
          raise InvalidInputError, "spec.encryptedData must be a mapping of key to ciphertext"
        end

        encrypted.keys.map(&:to_s)
      end
    end

    # @param name [String]
    # @param namespace [String, nil]
    # @param scope [Symbol]
    # @param type [String]
    # @param encrypted_keys [Array<String>]
    def initialize(name:, namespace:, scope:, type:, encrypted_keys:)
      @name = name
      @namespace = namespace
      @scope = scope
      @type = type
      @encrypted_keys = encrypted_keys.freeze
    end

    # Render the redacted editor buffer for the offline local edit: a Kubernetes
    # Secret manifest in which every existing key is shown as
    # {REDACTED_PLACEHOLDER}. The operator keeps a value by leaving the
    # placeholder, replaces it by typing a new value, adds keys by adding lines,
    # and removes keys by deleting lines.
    #
    # By default the keys sit under `data` (so replacements are base64, matching
    # the rest of the tool). With `string_data: true` they sit under
    # `stringData`, so replacements/new keys are entered as plaintext.
    #
    # @param commented [Boolean] include the explanatory header comment.
    # @param string_data [Boolean] place the keys under `stringData` (plaintext)
    #   instead of `data` (base64).
    # @return [String] YAML suitable to hand to {RKSeal::Editor}.
    def to_buffer(commented: true, string_data: false)
      body = {
        "apiVersion" => Secret::API_VERSION,
        "kind" => Secret::KIND,
        "metadata" => { "name" => name, "namespace" => namespace },
        "type" => type,
        (string_data ? "stringData" : "data") =>
          encrypted_keys.to_h { |key| [key, REDACTED_PLACEHOLDER] }
      }

      yaml = YAML.dump(body).delete_prefix("---\n")
      commented ? "#{buffer_header(string_data)}#{yaml}" : yaml
    end

    private

    def buffer_header(string_data)
      entry = string_data ? "plaintext" : "base64"
      <<~HEADER
        # rkseal: LOCAL edit of a SealedSecret (offline -- cluster state is NOT read).
        #
        # Existing values cannot be decrypted, so each key shows #{REDACTED_PLACEHOLDER}.
        # On save:
        #   - leave a value as #{REDACTED_PLACEHOLDER} to KEEP its current sealed value untouched;
        #   - replace #{REDACTED_PLACEHOLDER} with a new #{entry} value to RE-SEAL that key (rehash);
        #   - add a new `key: value` line to seal a NEW key (#{entry} value);
        #   - delete a key's line to REMOVE it from the SealedSecret.
        #
        # Scope (#{scope}) is preserved and cannot be changed here: kept values
        # cannot be re-sealed under a new scope. name/namespace are fixed too.
      HEADER
    end
  end
end
