# frozen_string_literal: true

RSpec.describe RKSeal::SecureWorkspace do
  # The security-critical contract: plaintext must never touch persistent disk,
  # and the RAM-backed scratch must always be torn down.

  # The crash-safety registry is process-global by design (a signal handler
  # must reach every live workspace). Clear it between examples so a workspace
  # registered in one example -- holding a now-expired test double -- cannot be
  # swept by the signal/at_exit net of a later example.
  after { described_class.registry.clear }

  # Pretend to be a given OS by stubbing the one thing the selection logic reads.
  def stub_host_os(host)
    stub_const("RbConfig::CONFIG", RbConfig::CONFIG.merge("host_os" => host))
  end

  # A medium double that records its lifecycle, so OS-agnostic behaviour
  # (registry, file creation, teardown ordering) can be tested without a real
  # RAM disk. It hands out a plain Dir.mktmpdir as its "RAM" directory.
  def fake_medium(dir:)
    medium = instance_spy("medium", provision: dir)
    allow(RKSeal::SecureWorkspace::LinuxMedium).to receive(:new).and_return(medium)
    medium
  end

  describe "per-OS medium selection" do
    let(:scratch_dir) { Dir.mktmpdir }

    after { FileUtils.remove_entry(scratch_dir) if File.directory?(scratch_dir) }

    context "when running on Linux" do
      it "provisions through a tmpfs-backed LinuxMedium" do
        stub_host_os("linux-gnu")
        medium = fake_medium(dir: scratch_dir)

        workspace = described_class.new(basename: "demo")
        path = workspace.provision

        expect(medium).to have_received(:provision)
        expect(File).to exist(path)
        workspace.teardown
      end
    end

    context "when running on macOS" do
      it "provisions through an hdiutil-backed MacosMedium" do
        stub_host_os("darwin25")
        medium = instance_spy("macos_medium", provision: scratch_dir)
        allow(RKSeal::SecureWorkspace::MacosMedium).to receive(:new).and_return(medium)

        workspace = described_class.new
        workspace.provision

        expect(RKSeal::SecureWorkspace::MacosMedium).to have_received(:new)
        expect(medium).to have_received(:provision)
        workspace.teardown
      end
    end

    context "when running on an unsupported platform" do
      it "raises WorkspaceError and never falls back to an on-disk temp file" do
        stub_host_os("mswin32")

        expect { described_class.new }
          .to raise_error(RKSeal::WorkspaceError, /no RAM-backed scratch medium/)
      end
    end
  end

  describe ".with" do
    let(:scratch_dir) { Dir.mktmpdir }

    after { FileUtils.remove_entry(scratch_dir) if File.directory?(scratch_dir) }

    before { stub_host_os("linux-gnu") }

    it "yields a usable RAM-backed path and returns the block's value" do
      fake_medium(dir: scratch_dir)

      result = described_class.with(basename: "demo") do |path|
        expect(File).to exist(path)
        File.write(path, "secret-plaintext")
        :block_value
      end

      expect(result).to eq(:block_value)
    end

    it "creates the scratch file with 0600 permissions" do
      fake_medium(dir: scratch_dir)

      described_class.with do |path|
        mode = File.stat(path).mode & 0o777
        expect(mode).to eq(described_class::FILE_MODE)
      end
    end

    it "tears the workspace down when the block returns normally" do
      medium = fake_medium(dir: scratch_dir)
      captured = nil

      described_class.with { |path| captured = path }

      expect(medium).to have_received(:teardown)
      expect(File).not_to exist(captured)
    end

    it "tears the workspace down even when the block raises" do
      medium = fake_medium(dir: scratch_dir)
      captured = nil

      expect do
        described_class.with do |path|
          captured = path
          raise "boom from the editing block"
        end
      end.to raise_error("boom from the editing block")

      expect(medium).to have_received(:teardown)
      expect(File).not_to exist(captured)
    end

    it "shreds the file contents before unlinking so plaintext does not linger" do
      fake_medium(dir: scratch_dir)
      observed_before_unlink = nil

      # Spy on unlink to capture what is on disk the instant before removal.
      allow(File).to receive(:unlink).and_wrap_original do |original, target|
        observed_before_unlink = File.read(target)
        original.call(target)
      end

      described_class.with { |path| File.write(path, "TOP-SECRET-VALUE") }

      expect(observed_before_unlink).not_to include("TOP-SECRET-VALUE")
    end

    it "raises WorkspaceError instead of falling back to an on-disk temp file" do
      medium = instance_spy("medium")
      allow(medium).to receive(:provision)
        .and_raise(RKSeal::WorkspaceError, "no writable tmpfs mount")
      allow(RKSeal::SecureWorkspace::LinuxMedium).to receive(:new).and_return(medium)

      expect { described_class.with { |_path| :never } }
        .to raise_error(RKSeal::WorkspaceError, /tmpfs/)
      # Teardown is idempotent: provision's own rescue and .with's ensure may
      # both fire it, which is exactly the safety-net behaviour we want.
      expect(medium).to have_received(:teardown).at_least(:once)
    end
  end

  describe "#teardown" do
    let(:scratch_dir) { Dir.mktmpdir }

    after { FileUtils.remove_entry(scratch_dir) if File.directory?(scratch_dir) }

    before { stub_host_os("linux-gnu") }

    it "is idempotent and does not raise when called repeatedly" do
      fake_medium(dir: scratch_dir)
      workspace = described_class.new
      workspace.provision

      expect { 3.times { workspace.teardown } }.not_to raise_error
    end

    it "does not raise on a never-provisioned workspace" do
      fake_medium(dir: scratch_dir)
      workspace = described_class.new

      expect { workspace.teardown }.not_to raise_error
    end

    it "never re-raises even if the underlying medium teardown fails" do
      medium = fake_medium(dir: scratch_dir)
      allow(medium).to receive(:teardown).and_raise("detach exploded")
      workspace = described_class.new
      workspace.provision

      expect { workspace.teardown }.not_to raise_error
    end

    it "removes the workspace from the crash-safety registry once torn down" do
      fake_medium(dir: scratch_dir)
      workspace = described_class.new
      workspace.provision

      expect(described_class.registry).to include(workspace)
      workspace.teardown
      expect(described_class.registry).not_to include(workspace)
    end
  end

  describe "crash safety" do
    let(:scratch_dir) { Dir.mktmpdir }

    after { FileUtils.remove_entry(scratch_dir) if File.directory?(scratch_dir) }

    before { stub_host_os("linux-gnu") }

    it "registers a provisioned workspace so a signal/at_exit sweep can find it" do
      fake_medium(dir: scratch_dir)
      workspace = described_class.new

      workspace.provision
      expect(described_class.registry).to include(workspace)

      workspace.teardown
    end

    it "registers the workspace BEFORE the RAM medium is provisioned" do
      # The window we are closing: on macOS the device is attached inside
      # @medium.provision (hdiutil attach, then newfs_hfs/mount). If a signal
      # lands during that call, the safety-net sweep must already see this
      # workspace -- so registration must happen before provision is invoked.
      registered_when_medium_ran = nil
      workspace = nil
      medium = instance_spy("medium")
      allow(medium).to receive(:provision) do
        registered_when_medium_ran = described_class.registry.include?(workspace)
        scratch_dir
      end
      allow(RKSeal::SecureWorkspace::LinuxMedium).to receive(:new).and_return(medium)
      workspace = described_class.new

      workspace.provision
      expect(registered_when_medium_ran).to be(true)
      workspace.teardown
    end

    it "detaches the attached device when a signal/teardown lands mid-provision" do
      # Simulate the exact leak window: the medium has already attached its RAM
      # device (state set) when a SIGINT/SIGTERM fires. The trap sweeps the
      # registry, which -- because we now register early -- includes this
      # half-provisioned workspace, so its teardown runs and the device is
      # detached instead of leaking.
      medium = instance_spy("medium")
      device_attached = false
      device_detached = false
      allow(medium).to receive(:provision) do
        device_attached = true # hdiutil attach succeeded
        described_class.registry.dup.each(&:teardown) # <- signal sweep fires here
        raise "interrupted mid-provision"
      end
      allow(medium).to receive(:teardown) { device_detached = true if device_attached }
      allow(RKSeal::SecureWorkspace::LinuxMedium).to receive(:new).and_return(medium)
      workspace = described_class.new

      expect { workspace.provision }.to raise_error(RKSeal::WorkspaceError, /interrupted/)
      expect(device_detached).to be(true)
      expect(described_class.registry).not_to include(workspace)
    end
  end

  describe "LinuxMedium", :allow_exec do
    subject(:medium) { described_class::LinuxMedium.new }

    it "raises WorkspaceError when no tmpfs mount is writable" do
      stub_const("#{described_class}::LinuxMedium::CANDIDATES", [].freeze)

      expect { medium.provision }
        .to raise_error(RKSeal::WorkspaceError, /no writable tmpfs mount/)
    end

    it "creates a private 0700 directory on the first usable tmpfs candidate" do
      base = Dir.mktmpdir
      stub_const("#{described_class}::LinuxMedium::CANDIDATES", [base].freeze)

      dir = medium.provision
      begin
        expect(dir).to start_with(base)
        expect(File.stat(dir).mode & 0o777).to eq(described_class::DIR_MODE)
      ensure
        medium.teardown
      end
      expect(File).not_to exist(dir)
    end

    it "teardown is a no-op when never provisioned" do
      expect { medium.teardown }.not_to raise_error
    end
  end

  # The real RAM-disk exercise. Guarded to darwin so it never runs on the wrong
  # OS; on macOS it provisions a genuine hdiutil RAM disk, round-trips a write,
  # and asserts both the file and the device are gone after teardown.
  describe "macOS RAM disk (real round-trip)", :allow_exec do
    before do
      skip "macOS-only: exercises a real hdiutil RAM disk" unless darwin?
    end

    def darwin?
      RbConfig::CONFIG["host_os"].match?(/darwin/i)
    end

    def rkseal_devices
      `hdiutil info`.scan(%r{^/dev/disk\d+}).select do |dev|
        `diskutil info #{dev} 2>/dev/null`.include?("rkseal")
      end
    end

    it "provisions a RAM disk, round-trips a write, and detaches on teardown" do
      workspace = described_class.new(basename: "realprobe")
      path = workspace.provision

      # The data lives on a /dev/disk RAM device, not on the persistent volume.
      backing = `df #{path}`.lines.last.split.first
      expect(backing).to start_with("/dev/disk")

      File.write(path, "kind: Secret\nstringData:\n  token: hunter2\n")
      expect(File.read(path)).to include("token: hunter2")
      expect(File.stat(path).mode & 0o777).to eq(described_class::FILE_MODE)

      workspace.teardown

      expect(File).not_to exist(path)
      # Give hdiutil a beat, then assert nothing rkseal-labelled is left attached.
      sleep 0.5
      expect(`hdiutil info`).not_to include(File.basename(path))
    end

    it "detaches the RAM disk even when the .with block raises" do
      before_count = rkseal_devices.size

      expect do
        described_class.with(basename: "realraise") do |path|
          File.write(path, "secret")
          raise "boom"
        end
      end.to raise_error("boom")

      sleep 0.5
      expect(rkseal_devices.size).to eq(before_count)
    end
  end
end
