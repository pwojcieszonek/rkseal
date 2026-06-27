# frozen_string_literal: true

module RKSeal
  module Commands
    # Orchestrates the `rkseal validate <namespace> <secret-name>` flow (and its
    # `--file <path>` variant).
    #
    # Asks the controller whether a SealedSecret is well-formed and decryptable
    # for its target, via `kubeseal --validate`. It does not decrypt or expose
    # anything; it is a pre-flight check you can run before committing or
    # applying. No editor, no workspace, no cluster Secret read, no file write.
    #
    # Input is either the local `<name>.yaml` in the output directory, or an
    # explicit file path (`file:`), which takes precedence and lets you validate
    # any SealedSecret manifest regardless of name.
    #
    # @example validate the local <name>.yaml
    #   RKSeal::Commands::Validate.new(namespace: "app", name: "db").call
    # @example validate an arbitrary file
    #   RKSeal::Commands::Validate.new(file: "out/db.yaml").call
    class Validate
      # @return [String, nil]
      attr_reader :namespace
      # @return [String, nil]
      attr_reader :name
      # @return [String, nil] explicit file path to validate, if given.
      attr_reader :file

      # @param namespace [String, nil] target namespace (positional CLI arg);
      #   may be nil when `file:` is used.
      # @param name [String, nil] Secret name (positional CLI arg); the
      #   `<name>.yaml` stem. May be nil when `file:` is used.
      # @param file [String, nil] explicit SealedSecret file path; overrides the
      #   `<name>.yaml` lookup when present.
      # @param kubeseal [RKSeal::Kubeseal] sealing adapter (validate).
      # @param output_dir [String] directory the `<name>.yaml` is read from (CWD).
      def initialize(namespace: nil, name: nil, file: nil,
                     kubeseal: Kubeseal.new, output_dir: Dir.pwd)
        @namespace = namespace
        @name = name
        @file = file
        @kubeseal = kubeseal
        @output_dir = output_dir
      end

      # Run the validation.
      #
      # @return [String] the validated path (so the CLI can name it in the
      #   "valid" message).
      # @raise [RKSeal::InvalidInputError] the target file does not exist.
      # @raise [RKSeal::ValidationError] the controller rejected the SealedSecret
      #   (the message carries the reason; the CLI prints it and exits non-zero).
      # @raise [RKSeal::CommandError] the validate operation itself failed.
      def call
        @kubeseal.ensure_available!
        path = target_path
        @kubeseal.validate(read_sealed(path))
        path
      end

      private

      # The file to validate: an explicit --file wins; otherwise <name>.yaml in
      # the output directory.
      def target_path
        return File.expand_path(@file) if @file

        File.expand_path(File.join(@output_dir, "#{@name}.yaml"))
      end

      def read_sealed(path)
        File.read(path)
      rescue SystemCallError => e
        raise InvalidInputError, "cannot read SealedSecret file #{path.inspect}: #{e.message}"
      end
    end
  end
end
