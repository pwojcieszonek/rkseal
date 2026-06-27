# frozen_string_literal: true

require "open3"

module RKSeal
  # Thin adapter over the `kubeseal` binary.
  #
  # Owns everything kubeseal-flag-shaped: scope, certificate source, and the
  # controller's name/namespace. Each public method maps to one kubeseal
  # invocation and returns its stdout (the produced SealedSecret YAML or a PEM
  # certificate). Nothing here parses YAML or knows about the domain model --
  # callers pass in manifest text and get sealed text back.
  #
  # Developed against kubeseal **v0.36.6**; flag names below assume that CLI.
  #
  # All process execution funnels through one private runner so that unit tests
  # stub a single seam (or stub the public methods directly). The runner must
  # never echo stdin (the plaintext Secret) into logs or error messages.
  #
  # The controller certificate is never cached on disk: an explicit `--cert` or
  # `SEALED_SECRETS_CERT` is used offline, otherwise it is fetched fresh from the
  # live controller on every invocation. This keeps a seal always bound to the
  # current context's controller key -- no stale or cross-cluster cert can sneak
  # in (see {#ensure_cert!}).
  class Kubeseal
    BINARY = "kubeseal"

    # Allowed sealing scopes, mapped to their kubeseal `--scope` argument.
    SCOPES = {
      strict: "strict",
      namespace_wide: "namespace-wide",
      cluster_wide: "cluster-wide"
    }.freeze

    # Substring kubeseal prints to stderr when the controller could decrypt-test
    # the SealedSecret but it is NOT valid. Anything else on a non-zero
    # `--validate` exit is treated as operational (CommandError), not a verdict.
    VALIDATION_FAILURE_MARKER = "unable to decrypt"

    # @param binary [String] override the executable name/path (testing/env).
    # @param controller_name [String, nil] `--controller-name` value.
    # @param controller_namespace [String, nil] `--controller-namespace` value.
    # @param cert [String, nil] `--cert <file|URL>` source; when nil and no env
    #   cert is present, the cert is fetched fresh from the controller per seal.
    def initialize(binary: BINARY, controller_name: nil, controller_namespace: nil,
                   cert: nil)
      @binary = binary
      @controller_name = controller_name
      @controller_namespace = controller_namespace
      @cert = cert
    end

    # Verify the kubeseal binary is present and executable; raise otherwise.
    # Called early so the flow fails fast on a missing dependency.
    #
    # @return [void]
    # @raise [RKSeal::DependencyMissingError] if `kubeseal` is not on PATH.
    def ensure_available!
      return if executable_on_path?(@binary)

      raise DependencyMissingError,
            "kubeseal not found on PATH (looked for #{@binary.inspect}). " \
            "Install it from https://github.com/bitnami-labs/sealed-secrets/releases."
    end

    # Confirm the encryption certificate is obtainable up front so a flow fails
    # fast before any editor opens. When an offline cert is configured (`--cert`
    # or the `SEALED_SECRETS_CERT` env var) nothing is contacted. Otherwise the
    # controller is probed with `--fetch-cert`; the fetched PEM is intentionally
    # discarded -- {#seal} re-fetches at seal time, so the freshest controller
    # key is always used and nothing is persisted between invocations.
    #
    # @return [void]
    # @raise [RKSeal::CommandError] if no offline cert is configured and the
    #   controller is unreachable (the underlying `--fetch-cert` exits non-zero).
    def ensure_cert!
      return if offline_cert?

      fetch_cert
      nil
    end

    # Seal a Secret manifest into a SealedSecret.
    #
    # Pipes `manifest_yaml` to kubeseal on stdin with `-o yaml` and the resolved
    # `--scope`. An explicit `--cert` is passed straight through; otherwise no
    # `--cert` is given and kubeseal resolves the cert itself -- from
    # `SEALED_SECRETS_CERT`, or failing that fresh from the live controller.
    # Returns the SealedSecret YAML on stdout.
    #
    # @param manifest_yaml [String] a full Secret manifest (from
    #   {RKSeal::Secret#to_manifest}).
    # @param scope [Symbol] one of {SCOPES} keys; defaults to :strict.
    # @return [String] SealedSecret YAML.
    # @raise [RKSeal::InvalidInputError] if scope is unknown.
    # @raise [RKSeal::CommandError] if kubeseal exits non-zero (e.g. controller
    #   unreachable, bad cert).
    def seal(manifest_yaml, scope: :strict)
      # `-o yaml` is mandatory: kubeseal defaults to JSON, so without it the
      # output written to `<name>.yaml` would actually contain JSON.
      argv = ["--scope", scope_flag(scope), "-o", "yaml"]
      cert_path = resolved_cert_path
      argv += ["--cert", cert_path] if cert_path
      argv += controller_flags

      run(*argv, stdin: manifest_yaml)
    end

    # Validate that a SealedSecret can be decrypted by the controller
    # (`kubeseal --validate`, SealedSecret piped on stdin). Contacts the cluster:
    # the controller performs the decrypt-test.
    #
    # kubeseal v0.36.6 exits 0 when valid and non-zero otherwise, printing the
    # reason to stderr. A non-zero exit whose stderr names a decrypt failure is a
    # validity verdict ({ValidationError}); any other non-zero exit (missing
    # binary, unreachable cluster, controller service not found) is operational
    # ({CommandError}) and says nothing about the SealedSecret itself.
    #
    # @param sealed_secret_yaml [String] a SealedSecret manifest.
    # @return [true] when the controller can decrypt it.
    # @raise [RKSeal::ValidationError] when the controller rejects it as invalid.
    # @raise [RKSeal::CommandError] on operational failures.
    def validate(sealed_secret_yaml)
      run("--validate", *controller_flags, stdin: sealed_secret_yaml)
      true
    rescue CommandError => e
      raise unless validation_failure?(e.stderr)

      raise ValidationError,
            "SealedSecret failed validation: #{e.stderr.strip}"
    end

    # Fetch the controller's public certificate (`kubeseal --fetch-cert`) so it
    # can be cached and reused, avoiding an API round-trip per seal.
    #
    # NOTE: unlike {#seal}, this method contacts the cluster API by design.
    #
    # @return [String] the certificate in PEM format.
    # @raise [RKSeal::CommandError] if the controller is unreachable.
    def fetch_cert
      run("--fetch-cert", *controller_flags)
    end

    # Blind-append freshly-encrypted items to an existing SealedSecret file
    # (`kubeseal --merge-into <file>`). Does NOT decrypt anything: it appends or
    # overwrites the items in the input Secret while leaving every other sealed
    # entry untouched. This is what powers the offline `edit --local` flow,
    # where kept keys must stay byte-for-byte unchanged.
    #
    # The certificate is resolved exactly like {#seal}: an explicit `--cert` is
    # passed through, otherwise kubeseal resolves it itself (env var, else fresh
    # from the controller). The output format is inherited from the existing
    # file, so `-o` is NOT forced here.
    #
    # @param manifest_yaml [String] Secret manifest with the items to add.
    # @param file [String] path to the existing SealedSecret to merge into.
    # @param scope [Symbol] sealing scope for the new items.
    # @return [void] mutates `file` in place.
    # @raise [RKSeal::CommandError] on kubeseal failure.
    def merge_into(manifest_yaml, file:, scope: :strict)
      argv = ["--merge-into", file, "--scope", scope_flag(scope)]
      cert_path = resolved_cert_path
      argv += ["--cert", cert_path] if cert_path
      argv += controller_flags

      run(*argv, stdin: manifest_yaml)
      nil
    end

    # Upgrade an existing SealedSecret to the controller's newest key without
    # exposing plaintext (`kubeseal --re-encrypt`). Out of scope for the initial
    # create/edit flows but part of the adapter surface.
    #
    # NOTE: contacts the cluster API by design.
    #
    # @param sealed_yaml [String] an existing SealedSecret manifest.
    # @return [String] the re-encrypted SealedSecret YAML.
    # @raise [RKSeal::CommandError] on kubeseal failure.
    def re_encrypt(sealed_yaml)
      run("--re-encrypt", "-o", "yaml", *controller_flags, stdin: sealed_yaml)
    end

    private

    # Translate a scope symbol into its kubeseal `--scope` argument.
    #
    # @raise [RKSeal::InvalidInputError] for an unknown scope.
    def scope_flag(scope)
      SCOPES.fetch(scope) do
        raise InvalidInputError,
              "Unknown scope #{scope.inspect}; expected one of #{SCOPES.keys.inspect}."
      end
    end

    # Whether an offline certificate source is configured, meaning {#ensure_cert!}
    # need not contact the controller. Either the injected `--cert` value or a
    # non-blank `SEALED_SECRETS_CERT` env var counts.
    def offline_cert?
      return true if @cert

      !env_cert.strip.empty?
    end

    # The `SEALED_SECRETS_CERT` env var, or an empty string.
    def env_cert
      ENV.fetch("SEALED_SECRETS_CERT", "")
    end

    # The cert file/URL to pass to `--cert`, or nil to let kubeseal resolve it
    # itself. Only an explicit `--cert` is forwarded; with none configured we
    # pass nil so kubeseal reads SEALED_SECRETS_CERT or fetches fresh from the
    # controller (the env var is never passed as a path -- kubeseal reads it).
    def resolved_cert_path
      @cert
    end

    # Whether kubeseal's stderr from a failed `--validate` is a validity verdict
    # (the controller could not decrypt) rather than an operational failure.
    def validation_failure?(stderr)
      return false unless stderr

      stderr.downcase.include?(VALIDATION_FAILURE_MARKER)
    end

    # `--controller-name` / `--controller-namespace` flags when configured.
    def controller_flags
      flags = []
      flags += ["--controller-name", @controller_name] if @controller_name
      flags += ["--controller-namespace", @controller_namespace] if @controller_namespace
      flags
    end

    # The single shell-out seam for this adapter. Uses Open3.capture3 with an
    # argv array (never a shell string) so user-supplied values can never be
    # interpreted by a shell -- no injection surface. On a non-zero exit it
    # raises CommandError carrying the scrubbed command label, status, and
    # stderr.
    #
    # SECURITY: `stdin` (the plaintext Secret manifest) is piped to the child
    # process but is NEVER included in the command label or any error message.
    # Only argv -- which holds flags and file paths, not secret values -- is
    # surfaced.
    #
    # @param argv [Array<String>] arguments passed after the binary name.
    # @param stdin [String, nil] data piped to the child process's stdin.
    # @return [String] captured stdout.
    # @raise [RKSeal::CommandError] on a non-zero exit.
    def run(*argv, stdin: nil)
      stdout, stderr, status = Open3.capture3(@binary, *argv, stdin_data: stdin || "")
      return stdout if status.success?

      raise CommandError.new(
        "kubeseal failed (exit #{status.exitstatus}): #{stderr.strip}",
        command: command_label(argv),
        status: status.exitstatus,
        stderr: stderr
      )
    end

    # Whether `name` resolves to an executable file on PATH (or is itself an
    # executable path).
    def executable_on_path?(name)
      return File.executable?(name) if name.include?(File::SEPARATOR)

      ENV.fetch("PATH", "").split(File::PATH_SEPARATOR).any? do |dir|
        File.executable?(File.join(dir, name))
      end
    end

    # A safe, human-readable label for error messages: the binary plus its argv.
    # Contains only flags/paths -- never stdin -- so it cannot leak secrets.
    def command_label(argv)
      [@binary, *argv].join(" ")
    end
  end
end
