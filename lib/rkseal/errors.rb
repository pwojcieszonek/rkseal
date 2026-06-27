# frozen_string_literal: true

module RKSeal
  # Error hierarchy for rkseal's fail-fast behavior.
  #
  # Every error rkseal raises on purpose descends from {RKSeal::Error}, so the
  # CLI entry point can rescue that one base class, print a single clean line,
  # and exit non-zero -- without swallowing genuinely unexpected exceptions
  # (those bubble up with a backtrace, as they should).
  #
  # Guidelines for raisers:
  # - Pick the most specific subclass that fits.
  # - Put a human-actionable message in the exception (what went wrong + what to
  #   do about it). Never put secret *values* in a message.
  # - Do not rescue-and-wrap unless you are adding context; prefer to let a
  #   specific error propagate.

  # Base class for all errors deliberately raised by rkseal.
  class Error < StandardError; end

  # A required external binary (`kubeseal` or `kubectl`) was not found on PATH,
  # or is not executable. Message should name the missing tool.
  class DependencyMissingError < Error; end

  # An external command ran but exited non-zero. Carries the command label,
  # exit status, and captured stderr so callers can surface a useful message
  # without re-deriving them.
  class CommandError < Error
    # @return [String] human label for the command (e.g. "kubeseal seal").
    attr_reader :command
    # @return [Integer, nil] process exit status, if one was produced.
    attr_reader :status
    # @return [String, nil] captured stderr (already scrubbed of secrets).
    attr_reader :stderr

    # @param message [String] human-readable summary.
    # @param command [String, nil] command label.
    # @param status [Integer, nil] exit status.
    # @param stderr [String, nil] captured stderr.
    def initialize(message = nil, command: nil, status: nil, stderr: nil)
      @command = command
      @status = status
      @stderr = stderr
      super(message)
    end
  end

  # The thing the user asked to operate on does not exist where it must.
  # Notably: `edit` was asked for a Secret that is absent from the cluster
  # (the message must point the user at `rkseal create`).
  class NotFoundError < Error; end

  # The user's input is unusable: an empty edit buffer, malformed YAML from the
  # editor, a manifest that is not a valid Kubernetes Secret, an unknown scope,
  # a `--from-file` path that does not exist, etc.
  class InvalidInputError < Error; end

  # A SealedSecret was checked against the controller and cannot be decrypted
  # (`kubeseal --validate` rejected it -- e.g. wrong scope, tampered ciphertext,
  # or sealed for a different name/namespace). Distinct from {CommandError},
  # which covers operational failures (missing binary, unreachable cluster) that
  # say nothing about the SealedSecret's validity. The message carries the
  # controller's stated reason.
  class ValidationError < Error; end

  # Something went wrong provisioning, mounting, or tearing down the RAM-backed
  # workspace (see {RKSeal::SecureWorkspace}). Treated as fatal: rkseal must not
  # silently fall back to on-disk scratch space.
  class WorkspaceError < Error; end

  # `$EDITOR` is unset/blank, could not be launched, or exited in a way that
  # signals the user aborted the edit.
  class EditorError < Error; end
end
