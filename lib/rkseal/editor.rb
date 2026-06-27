# frozen_string_literal: true

require "shellwords"

module RKSeal
  # Launches the user's `$EDITOR` on a buffer and returns the edited content.
  #
  # The editor never sees a persistent path: the caller supplies a RAM-backed
  # path from {RKSeal::SecureWorkspace}, this class seeds it with the initial
  # content, spawns `$EDITOR <path>`, blocks until the editor exits, then reads
  # the result back. It does not create, choose, or destroy the path -- that is
  # the workspace's job -- which keeps the "never on disk" guarantee in one
  # place.
  class Editor
    # Environment variables consulted, in priority order, to find the editor
    # command when none is injected explicitly.
    ENV_KEYS = %w[VISUAL EDITOR].freeze

    # vim-family editors persist buffer contents to files OUTSIDE the RAM-backed
    # path -- a swap file and the viminfo register/mark history -- which would
    # leak plaintext to persistent disk despite the workspace guarantee. Each
    # flag below suppresses one such sink (`-n` disables the swap file; `-i NONE`
    # disables viminfo). Keyed by the flag we test for, so an operator who has
    # already set it keeps their choice (we never duplicate it).
    VIM_HARDENING = { "-n" => ["-n"], "-i" => ["-i", "NONE"] }.freeze

    # @param command [String, nil] explicit editor command; when nil it is
    #   resolved from {ENV_KEYS} at edit time.
    def initialize(command: nil)
      @command = command
    end

    # Seed `path` with `content`, open it in `$EDITOR`, wait for the editor to
    # exit, and return the (possibly modified) file contents.
    #
    # Side effects: writes `content` to `path` and re-reads it; spawns and waits
    # on the editor process. Does not delete `path`.
    #
    # @param content [String] initial buffer contents (e.g. a seed manifest).
    # @param path [String] RAM-backed file path to edit on
    #   (from {RKSeal::SecureWorkspace}).
    # @return [String] the buffer contents after the editor exits.
    # @raise [RKSeal::EditorError] if no editor is configured, the editor cannot
    #   be launched, or it exits signaling the user aborted.
    def edit(content:, path:)
      # Resolve BEFORE writing any secret: if no editor is available we must
      # fail fast, before the plaintext ever lands in the buffer.
      argv = editor_argv

      File.write(path, content)
      launch(argv, path)
      File.read(path)
    end

    # Resolve the editor command that would be used (injected value or the first
    # set variable among {ENV_KEYS}). Exposed so a flow can fail fast *before*
    # provisioning a workspace if no editor is available.
    #
    # @return [String] the resolved editor command.
    # @raise [RKSeal::EditorError] if none is set.
    def resolve_command
      candidate = @command || env_command
      if candidate.nil? || candidate.strip.empty?
        raise EditorError,
              "no editor configured: set $VISUAL or $EDITOR (e.g. `export EDITOR=vim`)"
      end

      candidate
    end

    private

    attr_reader :command

    # First non-empty value among {ENV_KEYS}, honouring their priority order.
    def env_command
      ENV_KEYS.filter_map { |key| ENV.fetch(key, nil) }.find { |value| !value.strip.empty? }
    end

    # Split the resolved command into an argv array so editors carrying flags
    # (`code --wait`, `subl -w`, `emacsclient -nw`) launch correctly without a
    # shell. The file path is appended as a separate, un-split element so a path
    # is never re-parsed for metacharacters.
    #
    # @return [Array<String>] the editor command split into argv tokens.
    # @raise [RKSeal::EditorError] if the command does not resolve to any token.
    def editor_argv
      tokens = Shellwords.split(resolve_command)
      raise EditorError, "editor command resolved to nothing" if tokens.empty?

      harden_side_files(tokens)
    end

    # For the vim family, inject the flags from {VIM_HARDENING} the operator has
    # not already set, so swap/viminfo never write the plaintext to disk. The
    # flags go right after the command and before any user arguments (and the
    # path, appended in {#launch}), which is where vim expects its options.
    # Other editors pass through untouched.
    def harden_side_files(tokens)
      command, *rest = tokens
      return tokens unless vim_family?(command)

      flags = VIM_HARDENING.except(*rest).values.flatten
      [command, *flags, *rest]
    end

    # Whether the editor binary is a vim variant (vim, vi, nvim, gvim, mvim, and
    # suffixed builds like vim.basic/vimx). Matched on the basename so a full
    # path still resolves.
    def vim_family?(command)
      name = File.basename(command)
      name.start_with?("vim", "nvim") || %w[vi gvim mvim].include?(name)
    end

    # Spawn the editor (no shell), wait for it, and translate any non-clean exit
    # into an {EditorError}. A non-zero status or a termination by signal both
    # mean "the user did not save a usable result" -- we treat them as aborts.
    def launch(argv, path)
      pid = Process.spawn(*argv, path)
      _, status = Process.wait2(pid)
      raise_on_failure(status, argv.first)
    rescue Errno::ENOENT
      raise EditorError, "could not launch editor: command not found (#{argv.first.inspect})"
    rescue SystemCallError => e
      raise EditorError, "could not launch editor #{argv.first.inspect}: #{e.message}"
    end

    def raise_on_failure(status, command_name)
      return if status.success?

      if status.signaled?
        raise EditorError,
              "editor #{command_name.inspect} was killed by signal #{status.termsig}; aborting"
      end

      raise EditorError,
            "editor #{command_name.inspect} exited with status #{status.exitstatus}; " \
            "treating as aborted edit"
    end
  end
end
