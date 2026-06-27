# frozen_string_literal: true

require "base64"
require "yaml"

module RKSeal
  # Domain model for the Kubernetes Secret that sits at the center of every
  # rkseal flow.
  #
  # The editor buffer is a *full* Kubernetes Secret manifest (not a custom
  # key->value format): the user controls `data` vs `stringData`, `type`, and
  # `metadata` (labels/annotations). This class is the single place that knows
  # how to:
  #
  #   - build the seed manifest shown when authoring a new Secret (`create`);
  #   - turn the live cluster representation (`kubectl get secret -o json`) into
  #     an editable buffer, keeping `data` as *base64* (deliberately NOT decoded
  #     to plaintext) and stripping controller/runtime metadata that must not be
  #     re-sealed;
  #   - parse the saved buffer back into a Secret, accepting both `data`
  #     (base64, verbatim) and `stringData` (plaintext) and normalizing both
  #     into a single base64 `data` map, with `stringData` winning per key;
  #   - render a Secret to the exact YAML that gets piped into `kubeseal`;
  #   - merge a `--from-file` value into the manifest under a chosen key.
  #
  # == Why the canonical form is base64, not plaintext
  #
  # A SealedSecret cannot be decrypted client-side. The only source of current
  # values for `edit` is the unsealed cluster Secret, whose `.data` is base64.
  # rkseal deliberately surfaces that base64 verbatim rather than decoding it to
  # plaintext: showing decoded plaintext in an on-screen/RAM buffer is a wider
  # exposure than the operator already accepts by running `kubectl get secret`,
  # and it lets binary/TLS payloads round-trip losslessly. The convenience of
  # plaintext entry is preserved through `stringData`, which the operator may
  # add in the buffer and which is folded into `data` on parse.
  #
  # It is a rich domain object: encoding, validation, and conversion live here,
  # on the data they operate on -- not in external "builder"/"converter" verb
  # classes.
  #
  # No method in this class shells out, touches disk, or talks to a cluster;
  # it is pure data transformation and is trivially unit-testable.
  #
  # rubocop:disable Metrics/ClassLength -- this is the gem's single rich domain
  # object: by design it owns all Secret encoding, parsing, validation, and the
  # buffer/manifest conversions, on the data they operate on. Splitting it into
  # verb classes (the anti-pattern this gem avoids) would scatter that cohesion
  # for no gain; the extra lines are docstrings and small, focused helpers.
  class Secret
    # Kubernetes apiVersion/kind this model represents.
    API_VERSION = "v1"
    KIND = "Secret"
    DEFAULT_TYPE = "Opaque"

    # `metadata` keys that the apiserver/controller populate at runtime and that
    # must be stripped before a Secret is re-sealed, so the buffer shows only
    # author-owned fields.
    RUNTIME_METADATA_KEYS = %w[
      creationTimestamp resourceVersion uid generation selfLink managedFields
      ownerReferences deletionTimestamp deletionGracePeriodSeconds finalizers
    ].freeze

    # Annotation kubectl injects that embeds the previous object (including its
    # data) -- must be dropped so a stale copy of the secret is never re-sealed.
    LAST_APPLIED_ANNOTATION = "kubectl.kubernetes.io/last-applied-configuration"

    # Required data keys per well-known Secret type. kubeseal does not validate
    # these (the failure would only surface on-cluster), so rkseal fails fast.
    REQUIRED_KEYS_BY_TYPE = {
      "kubernetes.io/tls" => %w[tls.crt tls.key],
      "kubernetes.io/dockerconfigjson" => %w[.dockerconfigjson]
    }.freeze

    # Kubernetes DNS-1123 subdomain: lowercase alphanumerics, `-` and `.`
    # internally, must start and end alphanumeric. Anchored so a leading `-`
    # (argument injection into kubectl/kubeseal), a `/` or `..` (path traversal
    # into the output filename), and uppercase are all rejected.
    DNS_NAME_PATTERN = /\A[a-z0-9]([-a-z0-9.]*[a-z0-9])?\z/
    # Maximum length of a DNS-1123 subdomain.
    DNS_NAME_MAX_LENGTH = 253

    # SealedSecret scope annotations -> rkseal scope symbol. Absence of both
    # means the default, strict scope.
    SCOPE_ANNOTATIONS = {
      "sealedsecrets.bitnami.com/cluster-wide" => :cluster_wide,
      "sealedsecrets.bitnami.com/namespace-wide" => :namespace_wide
    }.freeze

    # @return [String] the Secret name (from the CLI positional arg).
    attr_reader :name
    # @return [String] the namespace (from the CLI positional arg).
    attr_reader :namespace
    # @return [String] the Secret `type` (e.g. "Opaque", "kubernetes.io/tls").
    attr_reader :type
    # @return [Hash{String=>String}] data items keyed by data key, values held
    #   as *base64* (the canonical in-memory form), whether they originated from
    #   `data` (verbatim) or `stringData` (encoded on parse).
    attr_reader :data
    # @return [Hash] author-owned metadata (labels, annotations, ...) with
    #   runtime keys already stripped.
    attr_reader :metadata

    class << self
      # Build the seed manifest for `rkseal create`: a minimal, valid Secret
      # skeleton (correct apiVersion/kind/type, name + namespace filled in, no
      # data) intended to be rendered to a commented template the user fills in.
      #
      # @param name [String]
      # @param namespace [String]
      # @param type [String] defaults to {DEFAULT_TYPE}.
      # @return [RKSeal::Secret]
      def seed(name:, namespace:, type: DEFAULT_TYPE)
        new(name: name, namespace: namespace, type: type)
      end

      # Build a Secret from the JSON `kubectl get secret -o json` returns.
      #
      # Keeps `.data` as base64 (no decode), folds any `.stringData` in (encoded
      # to base64, winning per key), and strips {RUNTIME_METADATA_KEYS}, the
      # last-applied-configuration annotation, and `status` so the result
      # reflects only what the author controls. Entry point for the `edit` flow.
      #
      # @param json [String, Hash] raw JSON string or parsed Hash from kubectl.
      # @return [RKSeal::Secret]
      # @raise [RKSeal::InvalidInputError] if the JSON is malformed, not a
      #   Secret, or carries non-decodable base64 in `.data`.
      def from_kubectl_json(json)
        doc = json.is_a?(Hash) ? json : parse_json(json)
        from_document(doc, data_is_base64: true)
      end

      # Parse a saved editor buffer (full Secret manifest as YAML) back into a
      # Secret. Folds `data` (base64, verbatim) and `stringData` (plaintext) into
      # the canonical base64 {#data} map -- `stringData` wins per key -- and
      # validates required fields.
      #
      # @param yaml [String] the raw buffer contents the editor returned.
      # @return [RKSeal::Secret]
      # @raise [RKSeal::InvalidInputError] on empty buffer, YAML syntax errors,
      #   wrong kind/apiVersion, missing name/namespace, or non-decodable base64
      #   under `data`.
      def from_buffer(yaml)
        raise InvalidInputError, "the edit buffer is empty" if yaml.nil? || yaml.strip.empty?

        doc = parse_yaml(yaml)
        unless doc.is_a?(Hash)
          raise InvalidInputError, "the buffer is not a YAML mapping (expected a Secret manifest)"
        end

        from_document(doc, data_is_base64: false)
      end

      # Validate a CLI-supplied identifier (Secret name or namespace) against the
      # Kubernetes DNS-1123 subdomain rules. This is a security boundary: a value
      # such as `../../etc/foo`, `-ojson`, or one containing `/` must be rejected
      # *before* it reaches the editor, the cluster, kubectl/kubeseal argv, or the
      # `<name>.yaml` output path.
      #
      # @param field [String] human label for the value ("name" / "namespace").
      # @param value [String] the value to check.
      # @return [String] the validated value (for chaining).
      # @raise [RKSeal::InvalidInputError] if it is not a valid DNS-1123 subdomain.
      def validate_identifier!(field:, value:)
        raise InvalidInputError, "#{field} must not be empty" if value.nil? || value.empty?
        if value.length > DNS_NAME_MAX_LENGTH
          raise InvalidInputError,
                "#{field} #{value.inspect} is too long (max #{DNS_NAME_MAX_LENGTH} characters)"
        end
        return value if DNS_NAME_PATTERN.match?(value)

        raise InvalidInputError,
              "#{field} #{value.inspect} is not a valid Kubernetes name " \
              "(lowercase letters, digits, '-' and '.', must start and end alphanumeric)"
      end

      # Derive the sealing scope from a SealedSecret by inspecting its
      # `metadata.annotations`. Used by `edit` to preserve the existing scope of a
      # secret unless the operator overrides it. Accepts both the JSON kubectl
      # prints and the YAML of a local `<name>.yaml` (YAML is a JSON superset, so
      # one parser handles both). Unknown/absent annotations -> the default
      # :strict scope. Malformed input is tolerated (returns :strict) so a scope
      # probe never aborts the flow -- the caller has its own fallbacks.
      #
      # @param document [String, Hash] the SealedSecret as JSON/YAML text or a
      #   pre-parsed Hash.
      # @return [Symbol] :strict, :namespace_wide, or :cluster_wide.
      def scope_from_sealed_json(document)
        doc = document.is_a?(Hash) ? document : safe_parse(document)
        annotations = doc.is_a?(Hash) ? doc.dig("metadata", "annotations") : nil
        return :strict unless annotations.is_a?(Hash)

        SCOPE_ANNOTATIONS.find(-> { [nil, :strict] }) do |annotation, _|
          truthy_annotation?(annotations[annotation])
        end.last
      end

      private

      # Parse a SealedSecret document (JSON from kubectl or YAML from a local
      # file) into a Hash, returning nil rather than raising on malformed input.
      # YAML.safe_load parses JSON too, so a single call covers both sources. The
      # scope probe is best-effort and must not abort the edit flow.
      def safe_parse(text)
        parsed = YAML.safe_load(text, permitted_classes: [], aliases: false)
        parsed.is_a?(Hash) ? parsed : nil
      rescue Psych::SyntaxError
        nil
      end

      # k8s treats the scope annotation as set when its value is the string
      # "true" (the controller writes exactly that); be lenient about casing.
      def truthy_annotation?(value)
        value.to_s.strip.casecmp?("true")
      end

      # Shared construction for both cluster JSON and editor YAML. `data_is_base64`
      # toggles whether the parser-provided `data` values are trusted as base64
      # already (kubectl) or must merely be normalized/validated as base64 (buffer);
      # `stringData` is always plaintext and is encoded here.
      def from_document(doc, data_is_base64:)
        validate_kind!(doc)
        metadata = extract_metadata(doc)
        name = fetch_name(metadata, doc)
        namespace = metadata["namespace"] || doc.dig("metadata", "namespace")
        type = doc["type"] || DEFAULT_TYPE

        new(
          name: name,
          namespace: namespace,
          type: type,
          data: fold_data(doc["data"], doc["stringData"], data_is_base64: data_is_base64),
          metadata: strip_metadata(metadata)
        )
      end

      def parse_json(text)
        require "json"
        JSON.parse(text)
      rescue JSON::ParserError => e
        raise InvalidInputError, "kubectl did not return valid JSON: #{e.message}"
      end

      def parse_yaml(text)
        YAML.safe_load(text, permitted_classes: [], aliases: false)
      rescue Psych::SyntaxError => e
        raise InvalidInputError, "the buffer is not valid YAML: #{e.message}"
      end

      def validate_kind!(doc)
        kind = doc["kind"]
        api = doc["apiVersion"]
        unless kind == KIND
          raise InvalidInputError,
                "not a Kubernetes Secret (kind: #{kind.inspect})"
        end
        return if api == API_VERSION

        raise InvalidInputError,
              "unexpected apiVersion #{api.inspect} (expected #{API_VERSION.inspect})"
      end

      def extract_metadata(doc)
        metadata = doc["metadata"]
        return {} if metadata.nil?
        raise InvalidInputError, "metadata must be a mapping" unless metadata.is_a?(Hash)

        metadata
      end

      def fetch_name(metadata, _doc)
        name = metadata["name"]
        raise InvalidInputError, "the Secret is missing metadata.name" if blank?(name)

        name
      end

      # Merge base64 `data` and plaintext `stringData` into one base64 map.
      # stringData wins per key (Kubernetes semantics). data values are validated
      # as base64 regardless of source so a malformed buffer fails fast.
      def fold_data(raw_data, raw_string_data, data_is_base64:)
        data = normalize_data_map(raw_data, data_is_base64: data_is_base64)
        normalize_string_data(raw_string_data).each do |key, value|
          data[key] = Base64.strict_encode64(value)
        end
        data
      end

      def normalize_data_map(raw, data_is_base64:)
        return {} if raw.nil?
        unless raw.is_a?(Hash)
          raise InvalidInputError,
                "`data` must be a mapping of key to base64 value"
        end

        raw.each_with_object({}) do |(key, value), acc|
          acc[key.to_s] = validated_base64(key, value, trusted: data_is_base64)
        end
      end

      def normalize_string_data(raw)
        return {} if raw.nil?
        unless raw.is_a?(Hash)
          raise InvalidInputError, "`stringData` must be a mapping of key to plaintext value"
        end

        raw.transform_keys(&:to_s).transform_values { |value| stringify(value) }
      end

      # A `data` value must be valid base64. We strip surrounding whitespace (a
      # stray newline a user may introduce in the editor) before validating, and
      # re-emit canonical strict base64 so the in-memory form is consistent.
      def validated_base64(key, value, trusted:)
        text = stringify(value).strip
        decoded = Base64.strict_decode64(text)
        trusted ? text : Base64.strict_encode64(decoded)
      rescue ArgumentError
        raise InvalidInputError, "value for data key #{key.to_s.inspect} is not valid base64"
      end

      def strip_metadata(metadata)
        cleaned = metadata.except(*RUNTIME_METADATA_KEYS, "name", "namespace", "status")
        scrub_annotations(cleaned)
      end

      def scrub_annotations(metadata)
        annotations = metadata["annotations"]
        return metadata unless annotations.is_a?(Hash)

        remaining = annotations.except(LAST_APPLIED_ANNOTATION)
        return metadata.except("annotations") if remaining.empty?

        metadata.merge("annotations" => remaining)
      end

      def stringify(value)
        value.is_a?(String) ? value : value.to_s
      end

      def blank?(value)
        value.nil? || (value.respond_to?(:strip) && value.strip.empty?)
      end
    end

    # @param name [String]
    # @param namespace [String]
    # @param data [Hash{String=>String}] base64-encoded items.
    # @param type [String]
    # @param metadata [Hash] author-owned metadata (labels/annotations); name
    #   and namespace are tracked separately and need not be duplicated here.
    def initialize(name:, namespace:, data: {}, type: DEFAULT_TYPE, metadata: {})
      @name = name
      @namespace = namespace
      @data = data.freeze
      @type = type
      @metadata = metadata.freeze
    end

    # Render this Secret to the editor/view buffer representation: a complete
    # Secret manifest as a YAML string.
    #
    # By default the values are presented as `data` (base64): emitted verbatim
    # when present (the canonical, never-decoded form used by `edit` and `view`),
    # or as an empty `data` block for the `create` seed.
    #
    # In *plaintext mode* (`string_data:` for the editors, `reveal:` for
    # `view`) the value block is `stringData` instead: an empty `stringData`
    # block for the seed, or the base64 `data` decoded to readable plaintext for
    # a populated Secret. Decoding a populated Secret is an opt-in plaintext
    # exposure (folded back to `data` on parse / read-only for `view`).
    #
    # @param commented [Boolean] include the explanatory header/comments
    #   (true for the `create` seed; typically false for round-tripping).
    # @param reveal [Boolean] `view`'s plaintext switch (decode to `stringData`).
    # @param string_data [Boolean] the editors' plaintext switch; same effect as
    #   `reveal`. Default false -> the `data` (base64) block.
    # @return [String] YAML suitable to hand to {RKSeal::Editor} or to print.
    def to_buffer(commented: false, reveal: false, string_data: false)
      body = base_manifest
      apply_data_block(body, plaintext: reveal || string_data)

      yaml = dump_yaml(body)
      commented ? "#{buffer_header}#{yaml}" : yaml
    end

    # Render this Secret to the canonical manifest YAML piped into `kubeseal`.
    #
    # Emits a clean Secret with base64 `data` only (stringData has already been
    # folded in on parse). The scope annotation is NOT injected here -- scope is
    # applied by {RKSeal::Kubeseal#seal} via `--scope`. This method only
    # validates the scope argument and serializes the Secret.
    #
    # @param scope [Symbol] one of :strict, :namespace_wide, :cluster_wide.
    # @return [String] manifest YAML for kubeseal's stdin.
    # @raise [RKSeal::InvalidInputError] if scope is unknown.
    def to_manifest(scope: :strict)
      validate_scope!(scope)
      body = base_manifest
      body["data"] = data.dup unless data.empty?
      dump_yaml(body)
    end

    # Return a copy of this Secret with one item set from a file's contents
    # (for the `--from-file` feature). Binary-safe: the file's bytes are base64
    # encoded into the data map (consistent with the base64 canonical form).
    #
    # @param key [String] data key to set.
    # @param contents [String] the file's bytes (read by the caller).
    # @return [RKSeal::Secret] a new Secret with the item merged in.
    def with_value(key:, contents:)
      merged = data.merge(key.to_s => Base64.strict_encode64(contents))
      self.class.new(
        name: name, namespace: namespace, type: type, data: merged, metadata: metadata
      )
    end

    # @return [Boolean] true when there are no data items -- used to reject an
    #   empty edit buffer (fail fast).
    def empty?
      data.empty?
    end

    # Assert this Secret satisfies the required-key contract for its `type`.
    # Opaque imposes no requirement; TLS/dockerconfigjson do. kubeseal does not
    # check this, so rkseal fails fast before sealing an on-cluster-broken Secret.
    #
    # @return [void]
    # @raise [RKSeal::InvalidInputError] if a required key for {#type} is absent.
    def validate!
      raise InvalidInputError, "the Secret has no data items" if empty?

      missing = REQUIRED_KEYS_BY_TYPE.fetch(type, []).reject { |key| data.key?(key) }
      return if missing.empty?

      raise InvalidInputError,
            "Secret type #{type.inspect} requires #{missing.join(", ")} " \
            "(present: #{data.keys.sort.join(", ")})"
    end

    # Value equality over the author-owned fields (name, namespace, type, data,
    # metadata). Lets the `edit` flow detect an unchanged buffer and skip work.
    # Because `data` is the canonical base64 form, equal data means equal
    # plaintext regardless of whether it was entered via `data` or `stringData`.
    #
    # @param other [Object]
    # @return [Boolean]
    def ==(other)
      other.is_a?(Secret) &&
        name == other.name &&
        namespace == other.namespace &&
        type == other.type &&
        data == other.data &&
        metadata == other.metadata
    end
    alias eql? ==

    # @return [Integer] hash consistent with {#==}.
    def hash
      [self.class, name, namespace, type, data, metadata].hash
    end

    private

    # The shared apiVersion/kind/type/metadata envelope, without any data block.
    def base_manifest
      {
        "apiVersion" => API_VERSION,
        "kind" => KIND,
        "metadata" => manifest_metadata,
        "type" => type
      }
    end

    # Attach the right value block for a buffer. Default (base64) shows `data`:
    # an empty block for a brand-new Secret, or the verbatim map otherwise. In
    # plaintext mode it shows `stringData`: an empty block for the seed, or the
    # base64 `data` decoded to readable plaintext.
    def apply_data_block(body, plaintext:)
      if data.empty?
        body[plaintext ? "stringData" : "data"] = {}
      elsif plaintext
        body["stringData"] = revealed_data
      else
        body["data"] = data.dup
      end
    end

    # Decode the base64 data map to plaintext for `view --reveal`. Values
    # normally come from the cluster (already valid base64); we still map a
    # malformed value to InvalidInputError for consistency with the rest of the
    # model rather than letting a raw ArgumentError escape.
    def revealed_data
      data.transform_values do |value|
        Base64.strict_decode64(value)
      rescue ArgumentError
        raise InvalidInputError, "stored data value is not valid base64; cannot reveal"
      end
    end

    def manifest_metadata
      { "name" => name, "namespace" => namespace }.merge(metadata)
    end

    def validate_scope!(scope)
      return if %i[strict namespace_wide cluster_wide].include?(scope)

      raise InvalidInputError,
            "unknown scope #{scope.inspect} " \
            "(expected :strict, :namespace_wide, or :cluster_wide)"
    end

    # Dump without the leading "---" document marker for a cleaner buffer.
    def dump_yaml(body)
      YAML.dump(body).delete_prefix("---\n")
    end

    def buffer_header
      <<~HEADER
        # rkseal: edit this Kubernetes Secret, then save and quit.
        #
        # `data:` values are base64, shown VERBATIM -- they are never decoded to
        # plaintext. To set a value as readable plaintext, add it under a
        # `stringData:` block; on save, stringData is folded into data and wins
        # per key. For example, to change the value of `password` you would add:
        #
        #   stringData:
        #     password: my-new-plaintext-secret
        #
        # `type`, labels, and annotations under `metadata` are yours to edit.
        # An empty buffer (no data and no stringData) is rejected.
      HEADER
    end
  end
  # rubocop:enable Metrics/ClassLength
end
