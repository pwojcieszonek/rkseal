# frozen_string_literal: true

require "open3"
require "fileutils"
require "securerandom"

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
  # rubocop:disable Metrics/ClassLength -- the inline {CertCache} is co-located
  # here by design (the cert cache is intrinsic to this adapter and must not add
  # a new top-level require); that nested class accounts for the extra lines.
  class Kubeseal
    BINARY = "kubeseal"

    # Allowed sealing scopes, mapped to their kubeseal `--scope` argument.
    SCOPES = {
      strict: "strict",
      namespace_wide: "namespace-wide",
      cluster_wide: "cluster-wide"
    }.freeze

    # kubeseal's own defaults for the controller's identity. Used to name the
    # cache entry consistently when the caller does not override them, so a run
    # with implicit defaults and a run with explicit-but-identical flags share
    # one cached cert.
    DEFAULT_CONTROLLER_NAME = "sealed-secrets-controller"
    DEFAULT_CONTROLLER_NAMESPACE = "kube-system"

    # Substring kubeseal prints to stderr when the controller could decrypt-test
    # the SealedSecret but it is NOT valid. Anything else on a non-zero
    # `--validate` exit is treated as operational (CommandError), not a verdict.
    VALIDATION_FAILURE_MARKER = "unable to decrypt"

    # @param binary [String] override the executable name/path (testing/env).
    # @param controller_name [String, nil] `--controller-name` value.
    # @param controller_namespace [String, nil] `--controller-namespace` value.
    # @param cert [String, nil] `--cert <file|URL>` source; when nil and no env
    #   cert is present, the cert is fetched from the controller and cached.
    # @param refresh_cert [Boolean] when true, ignore any cached cert and
    #   overwrite it with a freshly fetched one (wired to `--refresh-cert`).
    def initialize(binary: BINARY, controller_name: nil, controller_namespace: nil,
                   cert: nil, refresh_cert: false)
      @binary = binary
      @controller_name = controller_name
      @controller_namespace = controller_namespace
      @cert = cert
      @refresh_cert = refresh_cert
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

    # Resolve the encryption certificate up front so a flow fails fast before any
    # editor opens. When an offline cert is configured (`--cert` or the
    # `SEALED_SECRETS_CERT` env var) nothing is contacted. Otherwise the cert is
    # resolved through the on-disk cache: a cached PEM is reused as-is, otherwise
    # it is fetched from the live controller and written to the cache (which is
    # what makes a subsequent {#seal} offline). `refresh_cert: true` skips the
    # cached copy and refetches.
    #
    # @return [void]
    # @raise [RKSeal::CommandError] if no offline cert is configured and the
    #   controller is unreachable (the underlying `--fetch-cert` exits non-zero).
    def ensure_cert!
      return if offline_cert?

      resolve_cached_cert_path
      nil
    end

    # Seal a Secret manifest into a SealedSecret.
    #
    # Pipes `manifest_yaml` to kubeseal on stdin with `-o yaml` and the resolved
    # `--scope`. The certificate is resolved offline-first: an explicit `--cert`
    # or the cached controller PEM is passed via `--cert` (no API round-trip);
    # only when neither is available does kubeseal fall back to the env var or
    # the controller itself. Returns the SealedSecret YAML on stdout.
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
    # The certificate is resolved offline-first, exactly like {#seal}: an
    # explicit `--cert` or the cached controller PEM is passed via `--cert` (no
    # API round-trip); only when neither is available does kubeseal fall back to
    # the env var or the controller. The output format is inherited from the
    # existing file, so `-o` is NOT forced here.
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

    # Resolve a cert file/URL to pass to `--cert`, or nil to let kubeseal fall
    # back to its own sources. Precedence: explicit `--cert` > env var (kubeseal
    # reads SEALED_SECRETS_CERT itself, so we pass nil) > cached/fetched PEM.
    def resolved_cert_path
      return @cert if @cert
      return nil unless env_cert.strip.empty?

      resolve_cached_cert_path
    end

    # Return the path to a usable cached controller PEM, fetching and writing it
    # first if absent (or if a refresh was requested). The cert is public, so the
    # cache file is world-readable.
    def cert_cache
      @cert_cache ||= CertCache.new(
        controller_namespace: @controller_namespace || DEFAULT_CONTROLLER_NAMESPACE,
        controller_name: @controller_name || DEFAULT_CONTROLLER_NAME
      )
    end

    def resolve_cached_cert_path
      return cert_cache.path if !@refresh_cert && cert_cache.exist?

      cert_cache.write(fetch_cert)
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

    # On-disk cache for the controller's PUBLIC certificate, so repeated seals do
    # not each hit the cluster for `--fetch-cert`. The cert is public, hence the
    # world-readable 0644 perms. One entry per controller identity, under the XDG
    # cache dir:
    #   ${XDG_CACHE_HOME:-$HOME/.cache}/rkseal/<namespace>/<name>.pem
    #
    # The namespace is a path segment rather than a `<namespace>-<name>` prefix
    # so two distinct identities can never collide on one file (e.g. `a-b`/`c`
    # vs `a`/`b-c`); a DNS-1123 name contains no `/`, so the layout is
    # unambiguous. Writes go through a temp file + atomic rename so a concurrent
    # seal never reads a half-written cert.
    #
    # Defined inline (not a separate file) so this adapter stays self-contained
    # and adds no new top-level require.
    class CertCache
      DIR_PERMS = 0o755
      FILE_PERMS = 0o644

      # @param controller_namespace [String]
      # @param controller_name [String]
      def initialize(controller_namespace:, controller_name:)
        @controller_namespace = controller_namespace
        @controller_name = controller_name
      end

      # @return [String] absolute path to this controller's cached PEM.
      def path
        File.join(cache_dir, @controller_namespace, "#{@controller_name}.pem")
      end

      # @return [Boolean] whether a cached PEM already exists.
      def exist?
        File.exist?(path)
      end

      # @return [String] the cached PEM contents.
      def read
        File.read(path)
      end

      # Persist a freshly fetched PEM (overwriting any existing entry) and return
      # its path so the caller can hand it to `--cert`.
      #
      # @param pem [String] certificate contents.
      # @return [String] the cache path that now holds the PEM.
      def write(pem)
        FileUtils.mkdir_p(File.dirname(path), mode: DIR_PERMS)
        write_atomically(pem)
        path
      end

      private

      # Write the PEM to a uniquely-named temp file in the same directory, then
      # rename it over the target. rename(2) is atomic within one filesystem, so
      # a concurrent seal sees either the old cert or the new one -- never a
      # half-written file. The temp file carries the final 0644 perms and is
      # removed if the rename never happens (e.g. an error mid-write).
      def write_atomically(pem)
        tmp = File.join(File.dirname(path), ".#{File.basename(path)}.#{SecureRandom.hex(8)}.tmp")
        File.write(tmp, pem)
        File.chmod(FILE_PERMS, tmp)
        File.rename(tmp, path)
      ensure
        File.unlink(tmp) if tmp && File.exist?(tmp)
      end

      # ${XDG_CACHE_HOME:-$HOME/.cache}/rkseal
      def cache_dir
        base = ENV.fetch("XDG_CACHE_HOME", nil)
        base = File.join(Dir.home, ".cache") if base.nil? || base.strip.empty?
        File.join(base, "rkseal")
      end
    end
  end
  # rubocop:enable Metrics/ClassLength
end
