# frozen_string_literal: true

require "thor"
require "io/console"

module RKSeal
  # Thor-based command-line interface: parses ARGV, validates options, and
  # dispatches to the orchestration commands. It is intentionally thin -- it
  # maps flags/positionals onto the {RKSeal::Commands} classes ({Create},
  # {Edit}, {Set}, ...), prints their {RKSeal::Commands::Result}, and turns
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

      # Thor's default echoes the offending argv into the message. `set` takes a
      # plaintext VALUE positionally, so a mis-quoted value would land in stderr
      # and every log that captures it; report only the count.
      def handle_argument_error(command, _error, args, _arity)
        name = [command.ancestor_name, command.name].compact.join(" ")
        raise Thor::InvocationError,
              "ERROR: \"#{basename} #{name}\" was called with #{args.size} argument(s)\n" \
              "Usage: \"#{banner(command)}\""
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

      --type seeds the buffer with the keys that type requires and validates the
      result before sealing. kubeseal itself checks nothing, and the apiserver
      would reject the unsealed Secret only on the cluster. Built-in types:

      #{SecretType.known.values.map { |t| "  #{t.name}: #{t.hint}" }.join("\n\n")}

      Any other type string is accepted as a custom type without key rules. An
      unknown name under kubernetes.io/ is rejected as a typo.
    LONGDESC
    method_option :scope, type: :string, default: "strict",
                          enum: %w[strict namespace-wide cluster-wide],
                          desc: "Sealing scope bound into the ciphertext"
    method_option :type, type: :string, default: Secret::DEFAULT_TYPE,
                         desc: "Secret type (built-in, e.g. kubernetes.io/tls, or custom)"
    method_option :cert, type: :string,
                         desc: "Controller certificate (file or URL); else --fetch-cert/env is used"
    method_option :"controller-name", type: :string,
                                      desc: "sealed-secrets controller name"
    method_option :"controller-namespace", type: :string,
                                           desc: "controller namespace"
    method_option :"from-file", type: :array, repeatable: true,
                                desc: "Pre-seed key=path value(s) into the buffer before editing " \
                                      "(repeat the flag or list several pairs after one)"
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

    desc "set NAMESPACE NAME KEY [VALUE]", "Seal one value into a SealedSecret, without an editor"
    long_desc <<~LONGDESC
      Seals a single key's value into an existing SealedSecret and writes
      <NAME>.yaml, without opening $EDITOR. Only that key is (re)sealed: every
      other entry's ciphertext is kept byte-for-byte (kubeseal --merge-into) and
      nothing is decrypted. An existing key is replaced; a new key is added.

      The value is taken from the first of: the VALUE argument; --from-file
      <path> (byte-exact, binary-safe); standard input when it is not a terminal
      (one trailing newline is dropped, so `echo` works); otherwise a hidden
      interactive prompt (also byte-exact, one trailing newline dropped). Prefer
      stdin, the prompt, or --from-file over VALUE: a positional argument lands
      in your shell history and is visible to other users via `ps`. The value is
      plaintext; pass --base64 if it is already base64 (e.g. copied from `view`;
      line wraps and other whitespace are ignored).

      A value read from stdin leaves nothing for the deploy confirmation to
      read, so --deploy then requires --yes.

      The SealedSecret comes from the local <NAME>.yaml when present (your
      working copy), otherwise from the live cluster object, which then becomes
      <NAME>.yaml. Scope, type, name, and namespace are preserved and cannot be
      changed here. If neither a local file nor a cluster SealedSecret exists,
      rkseal fails fast and points you at `create`.

      Deploy is opt-in exactly like `edit`: --deploy runs `kubectl apply` after
      surfacing the active kube context and asking you to confirm; --yes skips
      the prompt in non-interactive pipelines.
    LONGDESC
    method_option :"from-file", type: :string,
                                desc: "Read the value from this file (byte-exact, binary-safe)"
    method_option :base64, type: :boolean, default: false,
                           desc: "The value is already base64 (stored as-is after validation)"
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
    # Seal one value into an existing SealedSecret (no editor).
    #
    # @param namespace [String] target namespace.
    # @param name [String] Secret name (also the output filename stem).
    # @param key [String] data key to set.
    # @param value [String, nil] the value; nil to read it from --from-file,
    #   stdin, or a hidden prompt.
    # @return [void]
    def set(namespace, name, key, value = nil)
      validate_identifiers!(namespace, name)
      Secret.validate_data_key!(key)
      result = Commands::Set.new(
        namespace: namespace, name: name, key: key,
        value_source: value_source(key, value), base64: options["base64"],
        deploy: options["deploy"], assume_yes: options["yes"],
        kubectl: Kubectl.new, kubeseal: build_kubeseal
      ).call
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

    # Where `set` takes its value from, as a callable. Precedence: positional
    # VALUE, --from-file, piped stdin, hidden prompt. The first two are read
    # here, so a missing file fails before any cluster or cert work; stdin and
    # the prompt stay lazy so the command can source the SealedSecret and probe
    # the cert before anything is read or asked.
    def value_source(key, positional)
      from_file = options["from-file"]
      raise InvalidInputError, "give VALUE or --from-file, not both" if positional && from_file

      value = positional || (from_file && read_value_file(from_file))
      return -> { value } if value

      $stdin.tty? ? -> { ask_hidden("Value for #{key} (input hidden): ") } : stdin_source($stdin)
    end

    # Reading the value consumes stdin, so the deploy confirmation that would
    # follow reads EOF and Thor treats that as "no" -- a silently skipped deploy
    # that looks like success. Refuse up front instead.
    def stdin_source(stdin)
      if options["deploy"] && !options["yes"]
        raise InvalidInputError,
              "the value is read from stdin, so the deploy cannot be confirmed " \
              "interactively; add --yes"
      end

      -> { stdin.read.chomp }
    end

    def read_value_file(path)
      File.binread(path)
    rescue SystemCallError => e
      raise InvalidInputError, "--from-file #{path}: #{e.message}"
    end

    # Not Thor's `ask(echo: false)`: that strips the answer, and a secret must be
    # taken as typed (one trailing newline dropped). The terminal did not echo
    # the Enter, so the line is terminated by hand.
    def ask_hidden(question)
      say(question, nil, false)
      answer = $stdin.noecho(&:gets)
      say("")
      answer.to_s.chomp
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

    # Parse `--from-file key=path` tokens into a {key => path} Hash. Thor hands a
    # repeatable array option over as one array per flag occurrence, so both
    # `--from-file a=x b=y` and `--from-file a=x --from-file b=y` are flattened
    # into the same list. Splitting on the first "=" only keeps paths that
    # contain "=" intact.
    #
    # @return [Hash{String=>String}, nil] nil when the flag was not given.
    def parsed_from_file
      entries = options["from-file"]
      return nil if entries.nil?

      entries.flatten.each_with_object({}) do |entry, acc|
        key, path = entry.split("=", 2)
        if key.nil? || key.empty? || path.nil? || path.empty?
          raise InvalidInputError, "--from-file expects key=path, got #{entry.inspect}"
        end

        acc[key] = path
      end
    end

    # Build the kubeseal adapter from the cert/controller options. Dashed option
    # names are string keys (Thor does not auto-underscore them).
    #
    # The controller name/namespace are Kubernetes identifiers that flow straight
    # into kubeseal's `--controller-name`/`--controller-namespace` flags, so they
    # are validated as DNS-1123 here (same gate as the positional args) -- this
    # rejects flag-injection (`-oyaml`, a leading `-`) and NUL before any value
    # reaches the shell-out.
    def build_kubeseal
      controller_name = validated_controller("controller-name")
      controller_namespace = validated_controller("controller-namespace")
      Kubeseal.new(
        cert: options["cert"],
        controller_name: controller_name,
        controller_namespace: controller_namespace
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
      if result.deployed
        say("Deployed #{result.secret_name} to the cluster.")
      elsif options["deploy"]
        say("Not deployed: confirmation declined.")
      end
    end
  end
  # rubocop:enable Metrics/ClassLength
end
