# frozen_string_literal: true

require "thor"

module RKSeal
  # Thor-based command-line interface: parses ARGV, validates options, and
  # dispatches to the orchestration commands. It is intentionally thin -- it
  # maps flags/positionals onto {RKSeal::Commands::Create} /
  # {RKSeal::Commands::Edit}, prints their {RKSeal::Commands::Result}, and turns
  # the gem's fail-fast {RKSeal::Error}s into a single clean line + non-zero
  # exit. No business logic lives here.
  #
  # rubocop:disable Metrics/ClassLength -- length here is Thor's declarative
  # `method_option` surface (every flag for both subcommands plus their
  # long_desc help text), not logic. The two command bodies stay thin and
  # delegate straight to the orchestration classes.
  class CLI < Thor
    # kubeseal's `--scope` strings, as exposed on the CLI, mapped to the symbols
    # the command/adapter layers expect. Thor does not underscore enum values.
    SCOPE_SYMBOLS = {
      "strict" => :strict,
      "namespace-wide" => :namespace_wide,
      "cluster-wide" => :cluster_wide
    }.freeze

    # Make argument/usage errors (and our rescued errors) exit non-zero rather
    # than return 0, so the CLI is shell-script friendly.
    def self.exit_on_failure?
      true
    end

    class << self
      # `dispatch` is also Thor's own internal 4-arg command router, which
      # {Thor.start} calls. Preserve it under an alias so our public 1-arg entry
      # point can reuse the name (as the gem's contract requires) without
      # clobbering Thor's routing.
      alias thor_dispatch dispatch

      # Entry point used by `exe/rkseal`, and Thor's internal command router.
      #
      # Dual-role on arity:
      #   - called as `dispatch(argv)` (a single Array, from `exe/rkseal`): run
      #     {Thor.start} and translate any deliberately-raised {RKSeal::Error}
      #     into a one-line stderr message with a non-zero exit -- no backtrace.
      #     Thor's own parse errors keep their {exit_on_failure?} handling;
      #     unexpected exceptions propagate.
      #   - called by Thor internally (`dispatch(meth, args, opts, config)`):
      #     delegate to Thor's preserved router unchanged.
      #
      # @param args [Array] either `[argv]` (public) or Thor's four router args.
      # @return [void]
      def dispatch(*args)
        return thor_dispatch(*args) unless args.length == 1 && args.first.is_a?(Array)

        begin
          start(args.first)
        rescue RKSeal::Error => e
          warn(e.message)
          exit(1)
        end
      end
    end

    desc "create NAMESPACE NAME", "Author a new SealedSecret and write <NAME>.yaml"
    long_desc <<~LONGDESC
      Opens an empty, commented Kubernetes Secret manifest in $EDITOR on a
      RAM-backed buffer. After you save, the Secret is sealed with the
      controller's public key and written as <NAME>.yaml in the current
      directory. The plaintext buffer never touches persistent disk.

      Pre-seed values with --from-file key=path (repeatable; binary-safe, stored
      as base64). Pass --no-edit to seal the pre-seeded Secret directly without
      opening an editor (useful for TLS/dockerconfig/binary payloads).
    LONGDESC
    method_option :scope, type: :string, default: "strict",
                          enum: %w[strict namespace-wide cluster-wide],
                          desc: "Sealing scope bound into the ciphertext"
    method_option :type, type: :string, default: Secret::DEFAULT_TYPE,
                         desc: "Secret type (e.g. Opaque, kubernetes.io/tls)"
    method_option :cert, type: :string,
                         desc: "Controller certificate (file or URL); else --fetch-cert/env is used"
    method_option :"controller-name", type: :string,
                                      desc: "sealed-secrets controller name"
    method_option :"controller-namespace", type: :string,
                                           desc: "controller namespace"
    method_option :"refresh-cert", type: :boolean, default: false,
                                   desc: "Bypass the cert cache and re-fetch from the controller"
    method_option :"from-file", type: :array,
                                desc: "Pre-seed key=path value(s) into the buffer before editing"
    method_option :"no-edit", type: :boolean, default: false,
                              desc: "Seal the pre-seeded Secret directly, without opening $EDITOR"
    method_option :"string-data", type: :boolean, default: false,
                                  desc: "Edit values as plaintext stringData instead of base64 data"
    # Author a new SealedSecret.
    #
    # @param namespace [String] target namespace.
    # @param name [String] Secret name (also the output filename stem).
    # @return [void]
    def create(namespace, name)
      validate_identifiers!(namespace, name)
      result = Commands::Create.new(
        namespace: namespace, name: name,
        scope: scope_symbol, type: options["type"],
        from_file: parsed_from_file, no_edit: options["no-edit"],
        string_data: options["string-data"],
        kubeseal: build_kubeseal
      ).call
      report(result)
    end

    desc "edit NAMESPACE NAME", "Edit an existing SealedSecret and write <NAME>.yaml"
    long_desc <<~LONGDESC
      Reads the live unsealed Secret from the cluster (kubectl get secret -o
      json) -- the only way to recover current values -- and opens it in $EDITOR
      on a RAM-backed buffer, with `data` shown as base64 (verbatim, not decoded
      to plaintext). Add plaintext under `stringData` to change values readably.
      After you save, it re-seals and writes <NAME>.yaml in the current
      directory.

      If the Secret is absent from the cluster but a local <NAME>.yaml exists
      (e.g. you ran `create` but never deployed), rkseal switches automatically
      to an OFFLINE local edit -- no flag needed. There the existing values
      cannot be decrypted, so each key is shown as <redacted>: leave it to keep
      the sealed value, replace it to re-seal that key, add lines for new keys,
      or delete lines to remove keys. Scope is fixed (cannot be changed offline).
      If neither the cluster Secret nor a local file exists, rkseal fails fast
      and points you at `create`.

      Pass --local to force the offline path without contacting the cluster at
      all (useful when the cluster is unreachable). The automatic fallback only
      fires on a definitive "not found"; an unreachable cluster is surfaced as an
      error instead, since rkseal cannot then tell whether the secret exists
      remotely.

      Scope is preserved automatically: rkseal reads the existing SealedSecret's
      scope annotation from the cluster (falling back to the local <NAME>.yaml,
      then to strict). Pass --scope to override (cluster edits only; an offline
      edit cannot change scope).

      If you save without changing anything, rkseal writes no file -- and because
      there is nothing new to apply, a --deploy on an unchanged secret is a no-op
      (nothing is deployed).

      Deploy is opt-in only: pass --deploy to `kubectl apply` the result, which
      first surfaces the active kube context and asks you to confirm. In a
      non-interactive pipeline, add --yes to skip the prompt (still requires
      --deploy).
    LONGDESC
    method_option :scope, type: :string,
                          enum: %w[strict namespace-wide cluster-wide],
                          desc: "Sealing scope (overrides the secret's existing scope)"
    method_option :local, type: :boolean, default: false,
                          desc: "Force offline edit of the local file (auto-detected otherwise)"
    method_option :"string-data", type: :boolean, default: false,
                                  desc: "Edit values as plaintext stringData instead of base64 data"
    method_option :deploy, type: :boolean, default: false,
                           desc: "Apply the result to the cluster after writing (opt-in)"
    method_option :yes, type: :boolean, default: false,
                        desc: "Skip the deploy confirmation prompt (only with --deploy)"
    method_option :cert, type: :string,
                         desc: "Controller certificate (file or URL); else --fetch-cert/env is used"
    method_option :"controller-name", type: :string,
                                      desc: "sealed-secrets controller name"
    method_option :"controller-namespace", type: :string,
                                           desc: "controller namespace"
    method_option :"refresh-cert", type: :boolean, default: false,
                                   desc: "Bypass the cert cache and re-fetch from the controller"
    # Edit an existing SealedSecret. Reads current values from the cluster; if
    # the Secret is absent there but a local <NAME>.yaml exists, automatically
    # falls back to the offline local edit. `--local` forces the offline path.
    #
    # @param namespace [String] target namespace.
    # @param name [String] Secret name (also the output filename stem).
    # @return [void]
    def edit(namespace, name)
      validate_identifiers!(namespace, name)
      result = options["local"] ? edit_local(namespace, name) : edit_auto(namespace, name)
      report(result)
    end

    desc "reencrypt NAMESPACE NAME", "Re-encrypt a SealedSecret to the controller's newest key"
    long_desc <<~LONGDESC
      Rotates an existing SealedSecret onto the controller's current sealing key
      (`kubeseal --re-encrypt`) without ever exposing plaintext. The input is the
      SealedSecret itself: rkseal reads the local <NAME>.yaml if present,
      otherwise the live SealedSecret from the cluster. If neither exists, it
      fails fast and points you at `create`. The result is written back to
      <NAME>.yaml.

      Deploy works exactly like `edit`: pass --deploy to `kubectl apply`, which
      surfaces the active context and asks you to confirm (--yes skips the prompt
      in non-interactive pipelines).
    LONGDESC
    method_option :deploy, type: :boolean, default: false,
                           desc: "Apply the result to the cluster after writing (opt-in)"
    method_option :yes, type: :boolean, default: false,
                        desc: "Skip the deploy confirmation prompt (only with --deploy)"
    method_option :cert, type: :string,
                         desc: "Controller certificate (file or URL); else --fetch-cert/env is used"
    method_option :"controller-name", type: :string,
                                      desc: "sealed-secrets controller name"
    method_option :"controller-namespace", type: :string,
                                           desc: "controller namespace"
    method_option :"refresh-cert", type: :boolean, default: false,
                                   desc: "Bypass the cert cache and re-fetch from the controller"
    # Re-encrypt an existing SealedSecret to the newest controller key.
    #
    # @param namespace [String] target namespace.
    # @param name [String] Secret name (also the output filename stem).
    # @return [void]
    def reencrypt(namespace, name)
      validate_identifiers!(namespace, name)
      result = Commands::Reencrypt.new(
        namespace: namespace, name: name,
        deploy: options["deploy"], assume_yes: options["yes"],
        kubectl: Kubectl.new, kubeseal: build_kubeseal
      ).call
      report(result)
    end

    desc "validate [NAMESPACE NAME]", "Check a SealedSecret with the controller"
    long_desc <<~LONGDESC
      Asks the controller whether a SealedSecret is well-formed and decryptable
      for its target (`kubeseal --validate`). Nothing is decrypted or revealed --
      it is a safe pre-flight check before you commit or apply.

      By default it validates the local <NAME>.yaml for the given namespace/name.
      Pass --file <path> to validate an arbitrary SealedSecret manifest instead
      (NAMESPACE/NAME are then optional). On success it prints a "valid" line and
      exits 0; if the controller rejects the secret, it prints the reason and
      exits non-zero.
    LONGDESC
    method_option :file, type: :string,
                         desc: "Validate this SealedSecret file instead of <NAME>.yaml"
    method_option :cert, type: :string,
                         desc: "Controller certificate (file or URL); else --fetch-cert/env is used"
    method_option :"controller-name", type: :string,
                                      desc: "sealed-secrets controller name"
    method_option :"controller-namespace", type: :string,
                                           desc: "controller namespace"
    method_option :"refresh-cert", type: :boolean, default: false,
                                   desc: "Bypass the cert cache and re-fetch from the controller"
    # Validate a SealedSecret (local <NAME>.yaml, or --file <path>).
    #
    # @param namespace [String, nil] target namespace (omit with --file).
    # @param name [String, nil] Secret name (omit with --file).
    # @return [void]
    def validate(namespace = nil, name = nil)
      file = options["file"]
      raise InvalidInputError, "give NAMESPACE NAME or --file <path>" if file.nil? && name.nil?

      validate_identifiers!(namespace, name) unless file
      path = Commands::Validate.new(
        namespace: namespace, name: name, file: file, kubeseal: build_kubeseal
      ).call
      say("SealedSecret #{path} is valid.")
    end

    desc "view NAMESPACE NAME", "Print the live Secret for a SealedSecret (read-only)"
    long_desc <<~LONGDESC
      Reads the live unsealed Secret from the cluster and prints the full Secret
      manifest to STDOUT. Strictly read-only: no editor, no RAM workspace, no
      file is written.

      By default `data` is shown as raw base64 (verbatim, like `edit`). Pass
      --reveal to decode the values and print them as plaintext `stringData`.
      If the Secret is not present in the cluster, rkseal fails fast and points
      you at `create`.
    LONGDESC
    method_option :reveal, type: :boolean, default: false,
                           desc: "Decode data and show values as plaintext stringData"
    # Print the live Secret for a SealedSecret (read-only).
    #
    # @param namespace [String] target namespace.
    # @param name [String] Secret name.
    # @return [void]
    def view(namespace, name)
      validate_identifiers!(namespace, name)
      manifest = Commands::View.new(
        namespace: namespace, name: name, reveal: options["reveal"], kubectl: Kubectl.new
      ).call
      say(manifest)
    end

    desc "list [NAMESPACE]", "List SealedSecrets (metadata only, read-only)"
    long_desc <<~LONGDESC
      Lists the SealedSecret objects in the cluster as a table with columns
      NAMESPACE, NAME, SCOPE, and AGE. Give a NAMESPACE to scope the listing to
      one namespace; omit it to list across all namespaces.

      Read-only and metadata-only: rkseal prints only each object's
      name/namespace/scope/age -- never any encrypted data. No editor, no file is
      written.
    LONGDESC
    # List SealedSecrets (read-only, metadata only).
    #
    # @param namespace [String, nil] limit to this namespace; omit for all.
    # @return [void]
    def list(namespace = nil)
      Secret.validate_identifier!(field: "namespace", value: namespace) if namespace
      say(Commands::List.new(namespace: namespace, kubectl: Kubectl.new).call)
    end

    desc "version", "Print the rkseal version"
    long_desc "Print the installed rkseal gem version and exit."
    # @return [void]
    def version
      say("rkseal #{RKSeal::VERSION}")
    end

    private

    # The default `edit`. The local <NAME>.yaml is the working copy: when it is
    # absent from the cluster or carries un-deployed changes (its sealed payload
    # differs from the deployed SealedSecret), editing continues on it offline so
    # those changes are never silently discarded. Otherwise -- no local file, or
    # it matches what is deployed -- rkseal seeds the editor from the live cluster
    # Secret (the only way to show decrypted values). After a deploy the file
    # matches the cluster again, so full values come back. An unreachable cluster
    # is surfaced as an error (not silently taken offline); use --local to force
    # offline then.
    def edit_auto(namespace, name)
      if local_manifest?(name) && (reason = offline_reason(namespace, name))
        say(reason)
        return edit_local(namespace, name)
      end

      edit_cluster(namespace, name)
    rescue NotFoundError
      raise unless local_manifest?(name)

      say("Secret not found in the cluster; editing the local #{name}.yaml offline.")
      edit_local(namespace, name)
    end

    # When a local <NAME>.yaml exists, decide whether to edit it offline rather
    # than seed from the cluster. Returns the message to print when going offline
    # (the file is absent from the cluster, or diverges from the deployed
    # SealedSecret), or nil to seed from the cluster. A `NotFound` cluster
    # SealedSecret means it was never deployed -> offline; other kubectl errors
    # (e.g. unreachable) propagate.
    def offline_reason(namespace, name)
      cluster = Kubectl.new.get_sealedsecret(name: name, namespace: namespace)
      return nil unless SealedSecret.diverged?(read_local_manifest(name), cluster)

      "Local #{name}.yaml has changes not deployed to the cluster; editing it offline " \
        "(values shown as <redacted> -- a SealedSecret cannot be decrypted). " \
        "Deploy to make the cluster authoritative again."
    rescue NotFoundError
      "#{name} is not deployed to the cluster; editing the local #{name}.yaml offline."
    end

    # Recover current values from the live cluster Secret and re-seal.
    def edit_cluster(namespace, name)
      Commands::Edit.new(
        namespace: namespace, name: name,
        scope: scope_symbol, deploy: options["deploy"], assume_yes: options["yes"],
        string_data: options["string-data"],
        kubectl: Kubectl.new, kubeseal: build_kubeseal
      ).call
    end

    # The offline local edit: operate on the local <NAME>.yaml. Scope cannot be
    # overridden -- kept ciphertext cannot be re-sealed under a new scope.
    def edit_local(namespace, name)
      if options["scope"]
        raise InvalidInputError,
              "scope cannot be changed when editing a local-only SealedSecret " \
              "(kept values cannot be re-sealed under a new scope)"
      end

      Commands::EditLocal.new(
        namespace: namespace, name: name,
        deploy: options["deploy"], assume_yes: options["yes"],
        string_data: options["string-data"],
        kubectl: Kubectl.new, kubeseal: build_kubeseal
      ).call
    end

    # Whether a local <NAME>.yaml exists in the working directory (the same path
    # the commands read/write), making an offline fallback possible.
    def local_manifest?(name)
      File.file?(manifest_path(name))
    end

    # Read the local <NAME>.yaml (only called when {#local_manifest?} is true).
    def read_local_manifest(name)
      File.read(manifest_path(name))
    end

    def manifest_path(name)
      File.join(Dir.pwd, "#{name}.yaml")
    end

    # Validate the positional identifiers at the CLI boundary, before any editor,
    # cluster, or filesystem work -- this is the security gate against path
    # traversal and argument injection (see {RKSeal::Secret.validate_identifier!}).
    def validate_identifiers!(namespace, name)
      Secret.validate_identifier!(field: "namespace", value: namespace)
      Secret.validate_identifier!(field: "name", value: name)
    end

    # Translate the dashed CLI scope string into the symbol the command expects.
    # Thor's enum has already constrained it to a known value. Returns nil when
    # `--scope` was not given (only `edit` omits the default, so it can preserve
    # the secret's existing scope).
    def scope_symbol
      value = options["scope"]
      value.nil? ? nil : SCOPE_SYMBOLS.fetch(value)
    end

    # Parse repeatable `--from-file key=path` tokens into a {key => path} Hash.
    # Splitting on the first "=" only keeps paths that contain "=" intact.
    #
    # @return [Hash{String=>String}, nil] nil when the flag was not given.
    def parsed_from_file
      entries = options["from-file"]
      return nil if entries.nil?

      entries.each_with_object({}) do |entry, acc|
        key, path = entry.split("=", 2)
        if key.nil? || key.empty? || path.nil? || path.empty?
          raise InvalidInputError, "--from-file expects key=path, got #{entry.inspect}"
        end

        acc[key] = path
      end
    end

    # Build the kubeseal adapter from the cert/controller options. Dashed option
    # names are string keys (Thor does not auto-underscore them). `--refresh-cert`
    # bypasses the cert cache (`Kubeseal.new(refresh_cert:)`); it defaults to
    # false for every command that builds a kubeseal adapter.
    #
    # The controller name/namespace are Kubernetes identifiers that flow into the
    # on-disk cert-cache path, so they are validated as DNS-1123 here (same gate
    # as the positional args) -- this prevents `../`, `/`, a leading `-`, or NUL
    # from escaping the cache directory before any path is built.
    def build_kubeseal
      controller_name = validated_controller("controller-name")
      controller_namespace = validated_controller("controller-namespace")
      Kubeseal.new(
        cert: options["cert"],
        controller_name: controller_name,
        controller_namespace: controller_namespace,
        refresh_cert: options.fetch("refresh-cert", false)
      )
    end

    # Validate a controller flag as a DNS-1123 name when present; pass nil through
    # untouched (the adapter falls back to its own defaults).
    def validated_controller(flag)
      value = options[flag]
      return nil if value.nil?

      Secret.validate_identifier!(field: "--#{flag}", value: value)
    end

    # Print a one-line outcome. A nil output_path means the edit was a no-op.
    def report(result)
      if result.output_path.nil?
        say("No changes; nothing written.")
        return
      end

      say("Wrote #{result.output_path}")
      say("Deployed #{result.secret_name} to the cluster.") if result.deployed
    end
  end
  # rubocop:enable Metrics/ClassLength
end
