# frozen_string_literal: true

require "fileutils"
require "securerandom"
require "rbconfig"
require "tmpdir"
require "open3"

module RKSeal
  # Provides a RAM-backed scratch path for the plaintext edit buffer and
  # guarantees its destruction. This is the single enforcement point for the
  # hard rule: **plaintext must never touch persistent disk.**
  #
  # The medium is chosen per-OS behind one interface:
  #   - Linux: a tmpfs path (`/dev/shm`, or `$XDG_RUNTIME_DIR`).
  #   - macOS: an ephemeral `hdiutil`-backed RAM disk, attached for the duration
  #     of the edit and detached afterwards (macOS has no tmpfs/`/dev/shm`).
  #
  # There is **no on-disk `mktemp` fallback**. If a RAM-backed medium cannot be
  # provisioned, the workspace raises {RKSeal::WorkspaceError} rather than
  # degrade the security guarantee.
  #
  # The public API is block-scoped so callers cannot forget teardown: the path
  # exists only inside the block, and on block exit (normal, exception, or
  # signal) the file is best-effort shredded/overwritten and unlinked and any
  # RAM disk is detached. Signal handling and `at_exit` registration guard
  # against a crash leaking a mounted RAM disk. Secret values are never logged.
  #
  # rubocop:disable Metrics/ClassLength -- this single class deliberately holds
  # the workspace orchestration plus its two tightly-coupled per-OS medium
  # strategies (LinuxMedium, MacosMedium). They are one cohesive unit and the
  # gem keeps one layer per file, so splitting them out would scatter the
  # "never on disk" guarantee rather than clarify it.
  class SecureWorkspace
    # Filesystem permissions for the scratch file: owner read/write only.
    FILE_MODE = 0o600

    # Permissions for the (Linux) scratch *directory*: owner only.
    DIR_MODE = 0o700

    # Size of the macOS RAM disk. A few MB is plenty for a Secret manifest; the
    # buffer holds one small YAML document, never bulk data.
    RAM_DISK_BYTES = 8 * 1024 * 1024

    # Bytes per disk sector, used to convert {RAM_DISK_BYTES} into the sector
    # count `hdiutil attach ram://<sectors>` expects.
    SECTOR_BYTES = 512

    # Signals whose default action would terminate the process before `ensure`
    # blocks normally run; we trap them so teardown still fires.
    TRAPPED_SIGNALS = %w[INT TERM].freeze

    # Process-wide registry of live workspaces, swept by the `at_exit`/signal
    # safety net so a crash or Ctrl-C cannot leak a mounted RAM disk. Guarded by
    # a mutex because signal handlers can run concurrently with normal teardown.
    @registry = []
    @registry_mutex = Mutex.new
    @safety_net_installed = false

    class << self
      attr_reader :registry, :registry_mutex

      # Provision a RAM-backed scratch file, yield its path, and guarantee
      # teardown when the block returns or raises.
      #
      # @param basename [String] hint for the scratch file name (no secret data).
      # @yieldparam path [String] absolute path to the RAM-backed file.
      # @yieldreturn [Object] whatever the block returns is returned to caller.
      # @return [Object] the block's return value.
      # @raise [RKSeal::WorkspaceError] if a RAM-backed medium cannot be
      #   provisioned or mounted (never falls back to plain on-disk temp).
      def with(basename: "rkseal")
        workspace = new(basename: basename)
        path = workspace.provision
        yield path
      ensure
        workspace&.teardown
      end

      # Register a workspace in the process-wide safety net and lazily install
      # the `at_exit` hook and signal traps on first use.
      #
      # @param workspace [SecureWorkspace]
      # @return [void]
      def register(workspace)
        @registry_mutex.synchronize do
          install_safety_net unless @safety_net_installed
          @registry << workspace unless @registry.include?(workspace)
        end
      end

      # Drop a workspace from the safety net once it has torn itself down.
      #
      # @param workspace [SecureWorkspace]
      # @return [void]
      def unregister(workspace)
        @registry_mutex.synchronize { @registry.delete(workspace) }
      end

      private

      # Wire up the crash-safety net exactly once: an `at_exit` hook for normal
      # and exception exits, plus traps for INT/TERM that tear everything down
      # and then re-raise the default behaviour so the process still dies.
      def install_safety_net
        at_exit { sweep_registry }

        TRAPPED_SIGNALS.each do |signal|
          previous = Signal.trap(signal) { handle_signal(signal) }
          previous_handlers[signal] = previous
        end

        @safety_net_installed = true
      end

      # Tear down every still-live workspace. Best-effort: never raises, so it is
      # safe to run from `at_exit` and signal contexts.
      def sweep_registry
        @registry.dup.each(&:teardown)
      end

      # Saved prior signal handlers, so trapping INT/TERM chains to whatever was
      # installed before instead of swallowing the signal.
      def previous_handlers
        @previous_handlers ||= {}
      end

      # Signal handler: shred all workspaces, restore the previous disposition,
      # and re-raise so the process terminates as the user expects.
      def handle_signal(signal)
        sweep_registry
        restore_default(signal)
      end

      # Restore a signal to its previously-installed handler (or DEFAULT) and
      # re-send it to ourselves so termination proceeds.
      def restore_default(signal)
        previous = previous_handlers[signal]
        Signal.trap(signal, previous || "DEFAULT")
        Process.kill(signal, Process.pid)
      end
    end

    # @param basename [String] hint for the scratch file name (no secret data).
    def initialize(basename: "rkseal")
      @basename = sanitize_basename(basename)
      @medium = build_medium
      @path = nil
    end

    # Provision the RAM-backed medium and return the usable scratch path. The
    # caller is then responsible for invoking {#teardown} (prefer the
    # block-scoped {.with} which does this automatically).
    #
    # @return [String] absolute path to the RAM-backed file.
    # @raise [RKSeal::WorkspaceError] if provisioning/mounting fails.
    def provision
      return @path if @path

      # Register in the crash-safety net BEFORE touching any RAM medium, so a
      # SIGINT/SIGTERM landing mid-provision -- e.g. after `hdiutil attach`
      # succeeds but during `newfs_hfs`/`mount` -- still sweeps this workspace
      # and detaches the attached device. The sweep would otherwise miss a
      # half-provisioned workspace and leak an orphaned RAM device. Teardown is
      # idempotent and tolerates any partial state, so early registration is
      # safe and `unregister` on the rescue/teardown path keeps it accurate.
      self.class.register(self)

      directory = @medium.provision
      @path = File.join(directory, "#{@basename}-#{SecureRandom.hex(8)}")
      create_scratch_file(@path)
      @path
    rescue WorkspaceError
      teardown
      raise
    rescue StandardError => e
      teardown
      raise WorkspaceError, "failed to provision RAM-backed workspace: #{e.message}"
    end

    # Best-effort shred + unlink the scratch file and detach/teardown any RAM
    # disk. Idempotent and must not raise on a partially-provisioned workspace
    # (it runs from `ensure`/signal paths). Logs nothing sensitive.
    #
    # @return [void]
    def teardown
      shred_and_unlink(@path)
      @path = nil
      @medium.teardown
      self.class.unregister(self)
      nil
    rescue StandardError
      # Teardown is a safety net and must never raise. We have already nulled
      # @path so a retry is harmless; the RAM medium's own teardown retries a
      # transiently-busy detach internally.
      nil
    end

    private

    attr_reader :basename

    # Choose the RAM-backed medium for the current OS. Kept as a thin dispatch
    # over {#os_family} so the selection logic is unit-testable in isolation.
    def build_medium
      case os_family
      when :linux then LinuxMedium.new
      when :macos then MacosMedium.new(bytes: RAM_DISK_BYTES)
      else
        raise WorkspaceError,
              "no RAM-backed scratch medium for this platform " \
              "(#{RbConfig::CONFIG["host_os"]}); refusing on-disk fallback"
      end
    end

    # Classify the host OS from RbConfig. Returns :linux, :macos, or
    # :unsupported. Isolated so specs can drive each branch deterministically.
    def os_family
      host = RbConfig::CONFIG["host_os"]
      case host
      when /linux/i then :linux
      when /darwin|mac os/i then :macos
      else :unsupported
      end
    end

    # Strip anything that is not a safe filename fragment; the basename is a
    # hint, never trusted input, and must not let a caller escape the directory.
    def sanitize_basename(value)
      cleaned = value.to_s.gsub(/[^A-Za-z0-9_.-]/, "_")
      cleaned.empty? ? "rkseal" : cleaned
    end

    # Create the scratch file atomically with 0600 permissions. Using the
    # explicit mode on open closes the brief window an open-then-chmod would
    # leave the file world-readable.
    def create_scratch_file(path)
      File.open(path, File::WRONLY | File::CREAT | File::EXCL, FILE_MODE) { |file| file }
    end

    # Overwrite the file contents with random bytes before unlinking, so the
    # plaintext does not linger in freed RAM pages, then remove it. Best-effort:
    # the file living on RAM-backed storage means even a skipped shred never
    # reaches persistent disk.
    def shred_and_unlink(path)
      return if path.nil? || !File.exist?(path)

      overwrite_with_random(path)
      File.unlink(path)
    rescue StandardError
      nil
    end

    def overwrite_with_random(path)
      size = File.size(path)
      File.open(path, File::WRONLY) do |file|
        file.write(SecureRandom.random_bytes(size)) if size.positive?
        file.flush
        file.fsync
      end
    rescue StandardError
      nil
    end

    # RAM-backed medium for Linux: a 0700 directory on an existing tmpfs mount
    # (`/dev/shm` or `$XDG_RUNTIME_DIR`). tmpfs is already RAM, so there is
    # nothing to attach or detach -- provision makes a private subdirectory and
    # teardown removes it.
    class LinuxMedium
      # tmpfs mount points to try, in order of preference.
      CANDIDATES = ["/dev/shm", ENV.fetch("XDG_RUNTIME_DIR", nil)].freeze

      def initialize
        @dir = nil
      end

      # @return [String] absolute path to a fresh 0700 scratch directory.
      # @raise [RKSeal::WorkspaceError] if no tmpfs mount is writable.
      def provision
        base = CANDIDATES.compact.find { |candidate| usable?(candidate) }
        unless base
          raise WorkspaceError,
                "no writable tmpfs mount (/dev/shm or $XDG_RUNTIME_DIR) for the scratch buffer"
        end

        @dir = File.join(base, "rkseal-#{SecureRandom.hex(8)}")
        FileUtils.mkdir(@dir, mode: DIR_MODE)
        @dir
      end

      # @return [void]
      def teardown
        return if @dir.nil?

        FileUtils.remove_entry_secure(@dir) if File.directory?(@dir)
        @dir = nil
      rescue StandardError
        nil
      end

      private

      def usable?(path)
        File.directory?(path) && File.writable?(path)
      end
    end

    # RAM-backed medium for macOS: an ephemeral `hdiutil`-backed RAM disk.
    #
    # macOS has no tmpfs/`/dev/shm`, so the only way to keep plaintext off
    # persistent disk is a RAM disk:
    #   1. `hdiutil attach -nomount ram://<sectors>` allocates RAM and returns a
    #      raw device node (e.g. /dev/disk7) without mounting it.
    #   2. `newfs_hfs -v <volname> <device>` lays down a tiny HFS+ filesystem.
    #   3. mount it under a private 0700 directory in $TMPDIR (the *mount point*
    #      lives on disk but is empty; the *data* lives only on the RAM device).
    # Teardown unmounts and `hdiutil detach`es the device (with a short retry in
    # case it is transiently busy), then removes the empty mount point.
    class MacosMedium
      # How many times to retry a transiently-busy `hdiutil detach`.
      DETACH_ATTEMPTS = 5
      # Backoff between detach retries, in seconds.
      DETACH_BACKOFF = 0.2

      # @param bytes [Integer] RAM disk size; rounded up to whole sectors.
      def initialize(bytes:)
        @sectors = (bytes.to_f / SECTOR_BYTES).ceil
        @device = nil
        @mount_point = nil
      end

      # @return [String] absolute path to the mounted RAM disk root.
      # @raise [RKSeal::WorkspaceError] if attach/format/mount fails.
      def provision
        @device = attach_ram_device
        format_device(@device)
        @mount_point = make_mount_point
        mount(@device, @mount_point)
        @mount_point
      end

      # @return [void]
      def teardown
        unmount(@mount_point) if @mount_point
        detach_with_retry(@device) if @device
        remove_mount_point(@mount_point) if @mount_point
        @device = nil
        @mount_point = nil
      rescue StandardError
        nil
      end

      private

      # `hdiutil attach -nomount ram://<sectors>` prints the new device node on
      # stdout. We capture it and reject anything that does not look like a
      # /dev/disk path so a malformed result never reaches `detach`.
      def attach_ram_device
        out, status = run("hdiutil", "attach", "-nomount", "ram://#{@sectors}")
        device = out.to_s.strip.split.first
        unless status&.success? && device&.start_with?("/dev/")
          raise WorkspaceError, "hdiutil could not attach a RAM disk (status #{status&.exitstatus})"
        end

        device
      end

      def format_device(device)
        _out, status = run("newfs_hfs", "-v", "rkseal", device)
        return if status&.success?

        # Leave nothing attached if formatting failed.
        detach_with_retry(device)
        @device = nil
        raise WorkspaceError,
              "newfs_hfs could not format the RAM disk (status #{status&.exitstatus})"
      end

      def make_mount_point
        dir = File.join(Dir.tmpdir, "rkseal-mnt-#{SecureRandom.hex(8)}")
        FileUtils.mkdir(dir, mode: DIR_MODE)
        dir
      end

      # Mount the freshly-formatted device read-write at our private mount point.
      def mount(device, mount_point)
        _out, status = run("mount", "-t", "hfs", device, mount_point)
        return if status&.success?

        raise WorkspaceError, "could not mount the RAM disk (status #{status&.exitstatus})"
      end

      def unmount(mount_point)
        run("umount", mount_point)
      rescue StandardError
        nil
      end

      # `hdiutil detach` can fail with EBUSY if the volume was only just
      # unmounted; retry a few times before giving up. Never raises.
      def detach_with_retry(device)
        detached = DETACH_ATTEMPTS.times.any? do |attempt|
          _out, status = run("hdiutil", "detach", device)
          break true if status&.success?

          sleep(DETACH_BACKOFF) unless attempt == DETACH_ATTEMPTS - 1
          false
        end
        # Last resort: force detach. Still best-effort; we do not raise from
        # teardown.
        run("hdiutil", "detach", "-force", device) unless detached
      rescue StandardError
        nil
      end

      def remove_mount_point(mount_point)
        FileUtils.remove_entry(mount_point) if File.directory?(mount_point)
      rescue StandardError
        nil
      end

      # Run an external command with no shell, capturing stdout. Returns
      # [stdout, Process::Status]. Stderr is sent to /dev/null -- it could echo a
      # device path but never secret contents, and we surface our own messages.
      def run(*argv)
        out, _err, status = Open3.capture3(*argv)
        [out, status]
      end
    end
  end
  # rubocop:enable Metrics/ClassLength
end
