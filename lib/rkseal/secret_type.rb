# frozen_string_literal: true

require "base64"
require "json"

module RKSeal
  # The `type` of a Kubernetes Secret together with the contract that type
  # imposes on the Secret's contents.
  #
  # kubeseal never checks these contracts: it seals whatever it is given, and a
  # Secret that violates its type's rules is rejected only when the controller
  # unseals it on the cluster (visible solely in controller events). rkseal
  # therefore enforces them client-side, before sealing, so the operator gets
  # the error while the editor buffer is still in front of them.
  #
  # Per type the contract is:
  #
  #   - {#required_keys}: every key must be present with a non-empty value;
  #   - {#any_of_keys}: at least one must be present with a non-empty value
  #     (`kubernetes.io/basic-auth` needs `username` or `password`);
  #   - {#required_annotations}: `kubernetes.io/service-account-token` needs
  #     `kubernetes.io/service-account.name`; its data is filled in by the
  #     token controller, so an empty data map is legal for that type only;
  #   - value rules ({#check_value!}): a docker config must be a JSON object, a
  #     bootstrap token id/secret must match the documented alphabet/length;
  #   - identity rules ({#validate_identity!}): a bootstrap token Secret must
  #     live in `kube-system` and be named `bootstrap-token-<token-id>`, or the
  #     bootstrap authenticator ignores it.
  #
  # The same type object also seeds the `create` buffer with the keys the type
  # demands, so the operator fills in values instead of recalling key names.
  #
  # Types outside the registry are accepted as custom (Kubernetes allows any
  # type string) with no rules, except that an unknown name under a
  # `kubernetes.io/` prefix is rejected: that prefix is reserved for built-in
  # types, so an unknown one is a typo.
  #
  # rubocop:disable Metrics/ClassLength -- the registry table and the two
  # rule-carrying subclasses live here on purpose, so the whole type contract
  # is readable in one place; the excess lines are docstrings and the table.
  class SecretType
    OPAQUE = "Opaque"

    # Prefixes under which Kubernetes defines its built-in types. An unknown type
    # here cannot be a legitimate custom type.
    RESERVED_PREFIXES = %w[kubernetes.io/ bootstrap.kubernetes.io/].freeze

    # @return [String] the type string as written in the manifest.
    attr_reader :name
    # @return [Array<String>] keys that must be present and non-empty.
    attr_reader :required_keys
    # @return [Array<String>] keys of which at least one must be non-empty.
    attr_reader :any_of_keys
    # @return [Array<String>] keys the consumer understands but does not require.
    attr_reader :optional_keys
    # @return [Array<String>] `metadata.annotations` that must be non-empty.
    attr_reader :required_annotations
    # @return [String] one-line guidance shown in the editor buffer header.
    attr_reader :hint

    class << self
      # Resolve a type string to its {SecretType}.
      #
      # @param name [String] the manifest `type`.
      # @return [RKSeal::SecretType] a registered type, or a rule-free custom one.
      # @raise [RKSeal::InvalidInputError] for an unknown type under a reserved
      #   Kubernetes prefix.
      def for(name)
        known.fetch(name) { custom(name) }
      end

      # @return [Hash{String=>RKSeal::SecretType}] every built-in type by name.
      def known
        @known ||= registry.to_h { |type| [type.name, type] }.freeze
      end

      private

      def custom(name)
        return new(name, hint: "custom type; no key rules are enforced") unless reserved?(name)

        raise InvalidInputError,
              "unknown Secret type #{name.inspect} under a reserved Kubernetes prefix " \
              "(known: #{known.keys.join(", ")})"
      end

      def reserved?(name)
        RESERVED_PREFIXES.any? { |prefix| name.start_with?(prefix) }
      end

      # rubocop:disable Metrics/MethodLength -- a flat data table, one entry per
      # built-in type; splitting it would only scatter the registry.
      def registry
        [
          new(OPAQUE, hint: "arbitrary keys and values"),
          new("kubernetes.io/service-account-token",
              required_annotations: %w[kubernetes.io/service-account.name],
              optional_keys: %w[token ca.crt namespace], data_optional: true,
              hint: "set the kubernetes.io/service-account.name annotation; " \
                    "the token controller fills in token/ca.crt/namespace"),
          DockerConfig.new("kubernetes.io/dockercfg", required_keys: %w[.dockercfg],
                                                      hint: ".dockercfg must be a JSON object " \
                                                            "(legacy ~/.dockercfg format)"),
          DockerConfig.new("kubernetes.io/dockerconfigjson",
                           required_keys: %w[.dockerconfigjson],
                           hint: ".dockerconfigjson must be a JSON object with an \"auths\" " \
                                 "map (~/.docker/config.json format)"),
          new("kubernetes.io/basic-auth", any_of_keys: %w[username password],
                                          hint: "at least one of username/password must be set"),
          new("kubernetes.io/ssh-auth", required_keys: %w[ssh-privatekey],
                                        hint: "ssh-privatekey holds the private key (PEM)"),
          new("kubernetes.io/tls", required_keys: %w[tls.crt tls.key],
                                   optional_keys: %w[ca.crt],
                                   hint: "tls.crt and tls.key hold the PEM certificate and key"),
          BootstrapToken.new("bootstrap.kubernetes.io/token",
                             required_keys: %w[token-id token-secret],
                             optional_keys: %w[description expiration
                                               usage-bootstrap-authentication
                                               usage-bootstrap-signing auth-extra-groups],
                             hint: "token-id is 6 and token-secret 16 chars of [a-z0-9]; the " \
                                   "Secret must be named bootstrap-token-<token-id> in kube-system")
        ]
      end
      # rubocop:enable Metrics/MethodLength
    end

    # @param name [String]
    # @param hint [String]
    # @param required_keys [Array<String>]
    # @param any_of_keys [Array<String>]
    # @param optional_keys [Array<String>]
    # @param required_annotations [Array<String>]
    # @param data_optional [Boolean] whether an empty data map is legal.
    def initialize(name, hint:, required_keys: [], any_of_keys: [], optional_keys: [],
                   required_annotations: [], data_optional: false)
      @name = name
      @required_keys = required_keys.freeze
      @any_of_keys = any_of_keys.freeze
      @optional_keys = optional_keys.freeze
      @required_annotations = required_annotations.freeze
      @data_optional = data_optional
      @hint = hint
    end

    # @return [Boolean] whether a Secret of this type may carry no data items.
    def data_optional?
      @data_optional
    end

    # @return [Boolean] whether this is a registered built-in type.
    def known?
      self.class.known.key?(name)
    end

    # The data skeleton for a new Secret of this type: every mandated key with
    # an empty value for the operator to fill in. Empty base64 is the empty
    # string, so the map is valid in the canonical base64 form as-is.
    #
    # @return [Hash{String=>String}]
    def seed_data
      (required_keys + any_of_keys).to_h { |key| [key, ""] }
    end

    # The annotation skeleton for a new Secret of this type.
    #
    # @return [Hash{String=>String}]
    def seed_annotations
      required_annotations.to_h { |annotation| [annotation, ""] }
    end

    # Enforce the full contract on a Secret about to be sealed.
    #
    # @param secret [RKSeal::Secret]
    # @return [void]
    # @raise [RKSeal::InvalidInputError] on the first violated rule.
    def validate!(secret)
      validate_keys!(secret.data.keys)
      validate_values!(secret.data)
      validate_annotations!(secret.metadata["annotations"] || {})
      validate_identity!(secret)
    end

    # Enforce the presence rules alone. The offline local edit can see only the
    # key set of kept ciphertext, so this is all it can check for those keys.
    #
    # @param keys [Array<String>] the data keys that will end up in the Secret.
    # @return [void]
    # @raise [RKSeal::InvalidInputError]
    def validate_keys!(keys)
      raise InvalidInputError, "the Secret has no data items" if keys.empty? && !data_optional?

      validate_required_keys!(keys)
      validate_any_of_keys!(keys)
    end

    # Enforce the value rules on the type-mandated keys that are present in
    # `data`; keys the type does not mandate are never inspected.
    #
    # @param data [Hash{String=>String}] base64 values keyed by data key.
    # @return [void]
    # @raise [RKSeal::InvalidInputError]
    def validate_values!(data)
      data.slice(*required_keys).each do |key, encoded|
        plain = decode(encoded)
        raise InvalidInputError, "required key #{key.inspect} is empty" if plain.empty?

        check_value!(key, plain)
      end
      validate_any_of_values!(data)
    end

    private

    def validate_required_keys!(keys)
      missing = required_keys - keys
      return if missing.empty?

      raise InvalidInputError,
            "Secret type #{name.inspect} requires #{missing.join(", ")} " \
            "(present: #{keys.sort.join(", ")})"
    end

    def validate_any_of_keys!(keys)
      return if any_of_keys.empty? || any_of_keys.intersect?(keys)

      raise InvalidInputError,
            "Secret type #{name.inspect} requires at least one of #{any_of_keys.join(", ")}"
    end

    def validate_any_of_values!(data)
      candidates = data.slice(*any_of_keys)
      return if candidates.empty? || candidates.values.any? { |encoded| !decode(encoded).empty? }

      raise InvalidInputError,
            "Secret type #{name.inspect} requires a non-empty value for at least one of " \
            "#{any_of_keys.join(", ")}"
    end

    def validate_annotations!(annotations)
      missing = required_annotations.reject { |key| present?(annotations[key]) }
      return if missing.empty?

      raise InvalidInputError,
            "Secret type #{name.inspect} requires the annotation #{missing.join(", ")} " \
            "under metadata.annotations"
    end

    # Hook: per-key rule on a decoded value. The message must never include the
    # value itself (it is secret material headed for stderr).
    def check_value!(_key, _plain); end

    # Hook: rules that bind the data to the Secret's name/namespace.
    def validate_identity!(_secret); end

    def decode(encoded)
      Base64.strict_decode64(encoded)
    end

    def present?(value)
      !value.nil? && !value.to_s.strip.empty?
    end

    # `kubernetes.io/dockercfg` and `kubernetes.io/dockerconfigjson`: the
    # apiserver rejects a value that does not parse as a JSON object, and the
    # kubelet reads image-pull credentials from the `auths` map of the newer
    # format.
    class DockerConfig < SecretType
      private

      def check_value!(key, plain)
        parsed = parse_json(key, plain)
        return unless key == ".dockerconfigjson" && !parsed["auths"].is_a?(Hash)

        raise InvalidInputError, "key #{key.inspect} must contain an \"auths\" JSON object"
      end

      # JSON::ParserError#message quotes the offending input, which here is
      # secret material, so the parser's message is deliberately not surfaced.
      def parse_json(key, plain)
        parsed = JSON.parse(plain)
        return parsed if parsed.is_a?(Hash)

        raise InvalidInputError, "key #{key.inspect} must be a JSON object"
      rescue JSON::ParserError
        raise InvalidInputError, "key #{key.inspect} is not valid JSON"
      end
    end

    # `bootstrap.kubernetes.io/token`: the bootstrap authenticator and the
    # TokenCleaner/BootstrapSigner controllers only consider Secrets in
    # `kube-system` whose name is `bootstrap-token-<token-id>`, and the token
    # itself is `<token-id>.<token-secret>` with a fixed alphabet and length.
    class BootstrapToken < SecretType
      NAMESPACE = "kube-system"
      NAME_PREFIX = "bootstrap-token-"
      VALUE_PATTERNS = {
        "token-id" => /\A[a-z0-9]{6}\z/,
        "token-secret" => /\A[a-z0-9]{16}\z/
      }.freeze

      private

      def check_value!(key, plain)
        pattern = VALUE_PATTERNS[key]
        return if pattern.nil? || pattern.match?(plain)

        raise InvalidInputError,
              "key #{key.inspect} must match #{pattern.inspect} (lowercase letters and digits)"
      end

      def validate_identity!(secret)
        unless secret.namespace == NAMESPACE
          raise InvalidInputError,
                "a bootstrap token Secret must live in the #{NAMESPACE} namespace " \
                "(got #{secret.namespace.inspect})"
        end

        expected = "#{NAME_PREFIX}#{decode(secret.data.fetch("token-id"))}"
        return if secret.name == expected

        raise InvalidInputError,
              "a bootstrap token Secret must be named #{expected} (got #{secret.name.inspect})"
      end
    end
  end
  # rubocop:enable Metrics/ClassLength
end
