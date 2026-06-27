# frozen_string_literal: true

require "open3"

module RKSeal
  # Thin adapter over the `kubectl` binary.
  #
  # Each public method maps to one kubectl invocation. Methods return raw
  # strings (JSON / context name) or nothing; this adapter does not parse the
  # Secret into the domain model -- {RKSeal::Secret.from_kubectl_json} does that.
  #
  # As with {RKSeal::Kubeseal}, all process execution funnels through one
  # private runner that is the single stub seam for unit tests. The runner must
  # never log Secret contents.
  class Kubectl
    BINARY = "kubectl"

    # kubectl prints this token to stderr when a resource is absent. Matched
    # case-insensitively to map the failure onto {NotFoundError}.
    NOT_FOUND_MARKER = "notfound"

    # @param binary [String] override the executable name/path (testing/env).
    def initialize(binary: BINARY)
      @binary = binary
    end

    # Verify the kubectl binary is present and executable; raise otherwise.
    #
    # @return [void]
    # @raise [RKSeal::DependencyMissingError] if `kubectl` is not on PATH.
    def ensure_available!
      return if executable_on_path?(@binary)

      raise DependencyMissingError,
            "kubectl not found on PATH (looked for #{@binary.inspect}). " \
            "Install it from https://kubernetes.io/docs/tasks/tools/."
    end

    # Read a Secret from the cluster as JSON
    # (`kubectl get secret <name> -n <namespace> -o json`). This is the only way
    # to recover the *current* plaintext of an existing SealedSecret, so it
    # drives the `edit` flow.
    #
    # @param name [String]
    # @param namespace [String]
    # @return [String] the JSON document kubectl prints on stdout.
    # @raise [RKSeal::NotFoundError] if the Secret does not exist (kubectl
    #   "NotFound"); the message must point the user at `rkseal create`.
    # @raise [RKSeal::CommandError] on any other kubectl failure (e.g. cluster
    #   unreachable, unknown namespace).
    def get_secret(name:, namespace:)
      run("get", "secret", name, "-n", namespace, "-o", "json")
    rescue CommandError => e
      raise unless not_found?(e.stderr)

      raise NotFoundError,
            "Secret #{name.inspect} not found in namespace #{namespace.inspect}. " \
            "Use `rkseal create #{namespace} #{name}` to author it first."
    end

    # Read a SealedSecret from the cluster as JSON
    # (`kubectl get sealedsecret <name> -n <namespace> -o json`). The `edit` flow
    # consults this to recover the existing seal's scope when it is not otherwise
    # known; callers rescue {NotFoundError} to fall back to the local file.
    #
    # @param name [String]
    # @param namespace [String]
    # @return [String] the JSON document kubectl prints on stdout.
    # @raise [RKSeal::NotFoundError] if the SealedSecret does not exist.
    # @raise [RKSeal::CommandError] on any other kubectl failure (e.g. cluster
    #   unreachable, unknown namespace, CRD not installed).
    def get_sealedsecret(name:, namespace:)
      run("get", "sealedsecret", name, "-n", namespace, "-o", "json")
    rescue CommandError => e
      raise unless not_found?(e.stderr)

      raise NotFoundError,
            "SealedSecret #{name.inspect} not found in namespace #{namespace.inspect}."
    end

    # List SealedSecrets as JSON (`kubectl get sealedsecret -o json`), scoped to
    # one namespace (`-n <namespace>`) or across all namespaces (`-A`) when none
    # is given. Drives the `list` flow.
    #
    # An empty namespace is not an error: kubectl returns a List object with an
    # empty `items: []`, so this does NOT map NotFound -- only operational
    # failures (cluster unreachable, CRD absent) surface, as {CommandError}.
    #
    # @param namespace [String, nil] a single namespace, or nil for all.
    # @return [String] the JSON List document kubectl prints on stdout.
    # @raise [RKSeal::CommandError] on any kubectl failure.
    def list_sealedsecrets(namespace: nil)
      scope = namespace ? ["-n", namespace] : ["-A"]
      run("get", "sealedsecret", *scope, "-o", "json")
    end

    # Apply a manifest file to the cluster (`kubectl apply -f <file>`). Only the
    # `edit` deploy step calls this, and only after {RKSeal::ContextGuard} has
    # approved the active context.
    #
    # @param file [String] path to the SealedSecret manifest to apply.
    # @return [String] kubectl's stdout (the apply result line).
    # @raise [RKSeal::CommandError] if apply fails.
    def apply(file:)
      run("apply", "-f", file)
    end

    # Return the active kube context (`kubectl config current-context`). Used by
    # {RKSeal::ContextGuard} to gate deploys.
    #
    # @return [String] the current context name (whitespace stripped).
    # @raise [RKSeal::CommandError] if kubectl cannot report a context.
    def current_context
      run("config", "current-context").strip
    end

    private

    # Whether kubectl's stderr indicates the resource was absent ("NotFound").
    def not_found?(stderr)
      return false unless stderr

      stderr.downcase.include?(NOT_FOUND_MARKER)
    end

    # The single shell-out seam for this adapter. Uses Open3.capture3 with an
    # argv array (never a shell string) so user-supplied names/namespaces can
    # never be interpreted by a shell -- no injection surface. On a non-zero
    # exit it raises CommandError carrying the scrubbed command label, status,
    # and stderr.
    #
    # SECURITY: any `stdin` is piped to the child but is NEVER echoed into the
    # command label or error message; only argv (subcommands, names, paths) is
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
        "kubectl failed (exit #{status.exitstatus}): #{stderr.strip}",
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
    # Contains only subcommands/paths -- never stdin -- so it cannot leak data.
    def command_label(argv)
      [@binary, *argv].join(" ")
    end
  end
end
