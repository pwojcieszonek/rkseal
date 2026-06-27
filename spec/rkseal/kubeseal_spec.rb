# frozen_string_literal: true

require "tmpdir"
require "fileutils"

RSpec.describe RKSeal::Kubeseal do
  subject(:kubeseal) { described_class.new(binary: "kubeseal") }

  # Isolate cert resolution from the real machine: every example gets a fresh,
  # empty XDG cache dir and a cleared SEALED_SECRETS_CERT, restored afterwards.
  # This keeps cache reads/writes inside a temp dir and stops a stray real cert
  # (env or ~/.cache) from changing what #seal/#ensure_cert! do.
  around do |example|
    Dir.mktmpdir("rkseal-cache-spec") do |dir|
      saved_xdg = ENV.fetch("XDG_CACHE_HOME", nil)
      saved_cert = ENV.fetch("SEALED_SECRETS_CERT", nil)
      ENV["XDG_CACHE_HOME"] = dir
      ENV.delete("SEALED_SECRETS_CERT")
      begin
        example.run
      ensure
        restore_env("XDG_CACHE_HOME", saved_xdg)
        restore_env("SEALED_SECRETS_CERT", saved_cert)
      end
    end
  end

  def restore_env(key, value)
    value.nil? ? ENV.delete(key) : ENV[key] = value
  end

  # The adapter's single shell-out seam. Stubbing it keeps every example below
  # off real binaries while still asserting the exact argv/stdin the public
  # methods build. Capture the invocation for later assertions.
  def stub_run(returning: "kind: SealedSecret\n")
    captured = {}
    allow(kubeseal).to receive(:run) do |*argv, **kwargs|
      captured[:argv] = argv
      captured[:stdin] = kwargs[:stdin]
      returning
    end
    captured
  end

  describe "#ensure_available!" do
    it "raises DependencyMissingError when kubeseal is not on PATH" do
      adapter = described_class.new(binary: "kubeseal-does-not-exist-xyz")
      allow(adapter).to receive(:executable_on_path?).and_return(false)

      expect { adapter.ensure_available! }
        .to raise_error(RKSeal::DependencyMissingError, /kubeseal not found on PATH/)
    end

    it "does not raise when the binary is resolvable" do
      allow(kubeseal).to receive(:executable_on_path?).and_return(true)

      expect { kubeseal.ensure_available! }.not_to raise_error
    end
  end

  describe "#ensure_cert!" do
    it "returns nil without contacting the controller when --cert is configured" do
      adapter = described_class.new(binary: "kubeseal", cert: "/certs/pub.pem")
      allow(adapter).to receive(:fetch_cert)

      expect(adapter.ensure_cert!).to be_nil
      expect(adapter).not_to have_received(:fetch_cert)
    end

    it "returns nil without contacting the controller when SEALED_SECRETS_CERT is set" do
      ENV["SEALED_SECRETS_CERT"] = "/certs/from-env.pem"
      allow(kubeseal).to receive(:fetch_cert)

      expect(kubeseal.ensure_cert!).to be_nil
      expect(kubeseal).not_to have_received(:fetch_cert)
    end

    it "treats a blank SEALED_SECRETS_CERT as no offline cert and fetches" do
      ENV["SEALED_SECRETS_CERT"] = "   "
      allow(kubeseal).to receive(:fetch_cert).and_return("-----BEGIN CERTIFICATE-----\n")

      kubeseal.ensure_cert!

      expect(kubeseal).to have_received(:fetch_cert)
    end

    it "fetches and caches when no offline cert and no cache exists yet" do
      allow(kubeseal).to receive(:fetch_cert).and_return("-----BEGIN CERTIFICATE-----\nPEM\n")

      expect(kubeseal.ensure_cert!).to be_nil
      expect(kubeseal).to have_received(:fetch_cert).once
      expect(File.read(kubeseal.send(:cert_cache).path)).to include("PEM")
    end

    it "reuses the cached cert without fetching again on the next call" do
      allow(kubeseal).to receive(:fetch_cert).and_return("-----BEGIN CERTIFICATE-----\n")

      kubeseal.ensure_cert! # populates the cache
      kubeseal.ensure_cert! # should hit the cache

      expect(kubeseal).to have_received(:fetch_cert).once
    end

    it "refetches and overwrites the cache when refresh_cert: true" do
      cache_path = described_class.new.send(:cert_cache).path
      FileUtils.mkdir_p(File.dirname(cache_path))
      File.write(cache_path, "STALE")
      refresher = described_class.new(binary: "kubeseal", refresh_cert: true)
      allow(refresher).to receive(:fetch_cert).and_return("FRESH-PEM")

      refresher.ensure_cert!

      expect(refresher).to have_received(:fetch_cert)
      expect(File.read(cache_path)).to eq("FRESH-PEM")
    end

    it "propagates CommandError when no offline cert is set and the controller is unreachable" do
      allow(kubeseal).to receive(:fetch_cert).and_raise(
        RKSeal::CommandError.new(
          "kubeseal failed (exit 1): cannot fetch certificate: no endpoints available",
          command: "kubeseal --fetch-cert",
          status: 1,
          stderr: "no endpoints available"
        )
      )

      expect { kubeseal.ensure_cert! }
        .to raise_error(RKSeal::CommandError, /cannot fetch certificate/)
    end
  end

  describe "#seal" do
    it "pipes the manifest to kubeseal on stdin with -o yaml and the resolved --scope" do
      allow(kubeseal).to receive(:fetch_cert).and_return("PEM")
      captured = stub_run

      kubeseal.seal("kind: Secret\n", scope: :namespace_wide)

      expect(captured[:stdin]).to eq("kind: Secret\n")
      # -o yaml is mandatory: kubeseal defaults to JSON output otherwise.
      expect(captured[:argv].each_cons(2)).to include(%w[-o yaml])
      expect(captured[:argv].each_cons(2)).to include(%w[--scope namespace-wide])
    end

    it "defaults to the strict scope" do
      allow(kubeseal).to receive(:fetch_cert).and_return("PEM")
      captured = stub_run

      kubeseal.seal("kind: Secret\n")

      expect(captured[:argv].each_cons(2)).to include(%w[--scope strict])
    end

    it "maps cluster_wide to the cluster-wide kubeseal flag" do
      allow(kubeseal).to receive(:fetch_cert).and_return("PEM")
      captured = stub_run

      kubeseal.seal("kind: Secret\n", scope: :cluster_wide)

      expect(captured[:argv].each_cons(2)).to include(%w[--scope cluster-wide])
    end

    it "passes the explicit --cert (and never fetches) when one is configured" do
      adapter = described_class.new(binary: "kubeseal", cert: "/certs/pub.pem")
      allow(adapter).to receive(:fetch_cert)
      captured = {}
      allow(adapter).to receive(:run) do |*argv, **_|
        captured[:argv] = argv
        ""
      end

      adapter.seal("kind: Secret\n")

      expect(captured[:argv].each_cons(2)).to include(%w[--cert /certs/pub.pem])
      expect(adapter).not_to have_received(:fetch_cert)
    end

    it "passes the cached cert path via --cert when no explicit/env cert is set" do
      allow(kubeseal).to receive(:fetch_cert).and_return("PEM")
      captured = stub_run

      kubeseal.seal("kind: Secret\n")

      cache_path = kubeseal.send(:cert_cache).path
      expect(captured[:argv].each_cons(2)).to include(["--cert", cache_path])
    end

    it "omits --cert (lets kubeseal read the env var) when SEALED_SECRETS_CERT is set" do
      ENV["SEALED_SECRETS_CERT"] = "/certs/from-env.pem"
      allow(kubeseal).to receive(:fetch_cert)
      captured = stub_run

      kubeseal.seal("kind: Secret\n")

      expect(captured[:argv]).not_to include("--cert")
      expect(kubeseal).not_to have_received(:fetch_cert)
    end

    it "passes controller name/namespace flags when configured" do
      adapter = described_class.new(
        binary: "kubeseal",
        controller_name: "sealed-secrets",
        controller_namespace: "kube-system",
        cert: "/certs/pub.pem"
      )
      captured = {}
      allow(adapter).to receive(:run) do |*argv, **_|
        captured[:argv] = argv
        ""
      end

      adapter.seal("kind: Secret\n")

      expect(captured[:argv].each_cons(2)).to include(%w[--controller-name sealed-secrets])
      expect(captured[:argv].each_cons(2)).to include(%w[--controller-namespace kube-system])
    end

    it "returns the SealedSecret YAML from stdout" do
      adapter = described_class.new(binary: "kubeseal", cert: "/certs/pub.pem")
      allow(adapter).to receive(:run)
        .and_return("apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\n")

      expect(adapter.seal("kind: Secret\n"))
        .to eq("apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\n")
    end

    it "raises InvalidInputError for an unknown scope" do
      stub_run

      expect { kubeseal.seal("kind: Secret\n", scope: :galaxy_wide) }
        .to raise_error(RKSeal::InvalidInputError, /Unknown scope :galaxy_wide/)
    end

    it "raises CommandError (with scrubbed stderr) when kubeseal exits non-zero" do
      adapter = described_class.new(binary: "kubeseal", cert: "/certs/pub.pem")
      allow(adapter).to receive(:run).and_raise(
        RKSeal::CommandError.new(
          "kubeseal failed (exit 1): bad cert",
          command: "kubeseal --scope strict -o yaml --cert /certs/pub.pem",
          status: 1,
          stderr: "bad cert"
        )
      )

      expect { adapter.seal("kind: Secret\n") }.to raise_error(RKSeal::CommandError) do |error|
        expect(error.status).to eq(1)
        expect(error.stderr).to eq("bad cert")
      end
    end

    it "never echoes the piped plaintext into the command label or error message" do
      adapter = described_class.new(binary: "kubeseal", cert: "/certs/pub.pem")
      secret = "kind: Secret\nstringData:\n  password: hunter2\n"
      status = instance_double(Process::Status, success?: false, exitstatus: 1)
      # Make the real runner raise so we can inspect what it surfaces, but stop
      # Open3 from actually spawning by stubbing capture3 underneath it.
      allow(Open3).to receive(:capture3)
        .and_return(["", "boom: the controller said no", status])

      expect { adapter.seal(secret) }.to raise_error(RKSeal::CommandError) do |error|
        expect(error.command).not_to include("hunter2")
        expect(error.message).not_to include("hunter2")
        expect(error.stderr).not_to include("hunter2")
      end
    end
  end

  describe "#validate" do
    it "runs `kubeseal --validate`, pipes the SealedSecret on stdin, and returns true" do
      captured = stub_run(returning: "")

      result = kubeseal.validate("kind: SealedSecret\n")

      expect(captured[:argv]).to include("--validate")
      expect(captured[:stdin]).to eq("kind: SealedSecret\n")
      expect(result).to be(true)
    end

    it "includes controller flags when configured" do
      adapter = described_class.new(
        binary: "kubeseal",
        controller_name: "sealed-secrets",
        controller_namespace: "kube-system"
      )
      captured = {}
      allow(adapter).to receive(:run) do |*argv, **_|
        captured[:argv] = argv
        ""
      end

      adapter.validate("kind: SealedSecret\n")

      expect(captured[:argv].each_cons(2)).to include(%w[--controller-name sealed-secrets])
      expect(captured[:argv].each_cons(2)).to include(%w[--controller-namespace kube-system])
    end

    it "raises ValidationError carrying the controller reason when it cannot decrypt" do
      allow(kubeseal).to receive(:run).and_raise(
        RKSeal::CommandError.new(
          "kubeseal failed (exit 1): error: unable to decrypt sealed secret: mysecret",
          command: "kubeseal --validate",
          status: 1,
          stderr: "error: unable to decrypt sealed secret: mysecret"
        )
      )

      expect { kubeseal.validate("kind: SealedSecret\n") }
        .to raise_error(RKSeal::ValidationError, /unable to decrypt sealed secret: mysecret/)
    end

    it "raises CommandError (not ValidationError) when the controller service is missing" do
      allow(kubeseal).to receive(:run).and_raise(
        RKSeal::CommandError.new(
          "kubeseal failed (exit 1): error: cannot get sealed secret service",
          command: "kubeseal --validate",
          status: 1,
          stderr: %(error: cannot get sealed secret service: services "x" not found)
        )
      )

      expect { kubeseal.validate("kind: SealedSecret\n") }
        .to raise_error(RKSeal::CommandError, /cannot get sealed secret service/)
    end

    it "raises CommandError (not ValidationError) when the cluster is unreachable" do
      allow(kubeseal).to receive(:run).and_raise(
        RKSeal::CommandError.new(
          "kubeseal failed (exit 1): error: invalid configuration",
          command: "kubeseal --validate",
          status: 1,
          stderr: "error: invalid configuration: no configuration has been provided"
        )
      )

      expect { kubeseal.validate("kind: SealedSecret\n") }
        .to raise_error(RKSeal::CommandError, /invalid configuration/)
    end
  end

  describe "#fetch_cert" do
    it "runs kubeseal --fetch-cert and returns the controller certificate (PEM)" do
      captured = stub_run(returning: "-----BEGIN CERTIFICATE-----\n")

      result = kubeseal.fetch_cert

      expect(captured[:argv]).to include("--fetch-cert")
      expect(result).to eq("-----BEGIN CERTIFICATE-----\n")
    end

    it "includes controller flags when configured" do
      adapter = described_class.new(
        binary: "kubeseal",
        controller_name: "sealed-secrets",
        controller_namespace: "kube-system"
      )
      captured = {}
      allow(adapter).to receive(:run) do |*argv, **_|
        captured[:argv] = argv
        ""
      end

      adapter.fetch_cert

      expect(captured[:argv].each_cons(2)).to include(%w[--controller-name sealed-secrets])
      expect(captured[:argv].each_cons(2)).to include(%w[--controller-namespace kube-system])
    end
  end

  describe "#merge_into" do
    it "blind-appends encrypted items to an existing SealedSecret file without forcing -o" do
      captured = stub_run

      kubeseal.merge_into("kind: Secret\n", file: "db.yaml", scope: :strict)

      expect(captured[:argv].each_cons(2)).to include(%w[--merge-into db.yaml])
      expect(captured[:stdin]).to eq("kind: Secret\n")
      # Output format is inherited from the existing file -- do NOT force -o.
      expect(captured[:argv]).not_to include("-o")
    end

    it "returns nil (mutation in place, nothing to hand back)" do
      stub_run

      expect(kubeseal.merge_into("kind: Secret\n", file: "db.yaml")).to be_nil
    end

    it "passes the offline-resolved cert via --cert (same precedence as #seal)" do
      adapter = described_class.new(binary: "kubeseal", cert: "/c.pem")
      captured = {}
      allow(adapter).to receive(:run) { |*argv, **_kw| captured[:argv] = argv }

      adapter.merge_into("kind: Secret\n", file: "db.yaml")

      expect(captured[:argv].each_cons(2)).to include(%w[--cert /c.pem])
    end
  end

  describe "#re_encrypt" do
    it "upgrades a SealedSecret via --re-encrypt with -o yaml, piping it on stdin" do
      captured = stub_run(returning: "kind: SealedSecret\n")

      result = kubeseal.re_encrypt("kind: SealedSecret\n")

      expect(captured[:argv]).to include("--re-encrypt")
      # -o yaml so the re-encrypted output is YAML, not kubeseal's default JSON.
      expect(captured[:argv].each_cons(2)).to include(%w[-o yaml])
      expect(captured[:stdin]).to eq("kind: SealedSecret\n")
      expect(result).to eq("kind: SealedSecret\n")
    end
  end

  describe RKSeal::Kubeseal::CertCache do
    subject(:cache) do
      described_class.new(
        controller_namespace: "kube-system",
        controller_name: "sealed-secrets-controller"
      )
    end

    let(:entry) { File.join("kube-system", "sealed-secrets-controller.pem") }

    it "names the entry <namespace>/<name>.pem under $XDG_CACHE_HOME/rkseal" do
      expect(cache.path)
        .to eq(File.join(ENV.fetch("XDG_CACHE_HOME"), "rkseal", entry))
    end

    it "falls back to ~/.cache/rkseal when XDG_CACHE_HOME is unset" do
      ENV.delete("XDG_CACHE_HOME")

      expect(cache.path).to eq(File.join(Dir.home, ".cache", "rkseal", entry))
    end

    it "gives two identities that share a <namespace>-<name> string distinct paths" do
      first = described_class.new(controller_namespace: "a-b", controller_name: "c")
      second = described_class.new(controller_namespace: "a", controller_name: "b-c")

      expect(first.path).not_to eq(second.path)
    end

    it "writes atomically, leaving no temp files behind" do
      cache.write("-----BEGIN CERTIFICATE-----\nABC\n")

      leftovers = Dir.children(File.dirname(cache.path)).grep(/\.tmp\z/)
      expect(leftovers).to be_empty
    end

    it "reports existence and round-trips the PEM through read" do
      expect(cache.exist?).to be(false)

      cache.write("-----BEGIN CERTIFICATE-----\nABC\n")

      expect(cache.exist?).to be(true)
      expect(cache.read).to eq("-----BEGIN CERTIFICATE-----\nABC\n")
    end

    it "writes the cert world-readable (0644) -- it is public, not secret" do
      cache.write("PEM")

      expect(File.stat(cache.path).mode & 0o777).to eq(0o644)
    end

    it "returns the path from #write so callers can pass it to --cert" do
      expect(cache.write("PEM")).to eq(cache.path)
    end
  end

  # The runner itself: exercised through a stubbed Open3 so no real binary runs.
  # Marked :allow_exec because it intentionally drives the `run` seam end to end
  # (the global guard would otherwise trip on Open3.capture3).
  describe "#run (private seam)", :allow_exec do
    let(:ok_status) { instance_double(Process::Status, success?: true, exitstatus: 0) }
    let(:fail_status) { instance_double(Process::Status, success?: false, exitstatus: 2) }

    it "invokes Open3.capture3 with an argv array (no shell string) and pipes stdin" do
      expect(Open3).to receive(:capture3)
        .with("kubeseal", "--scope", "strict", "-o", "yaml", stdin_data: "kind: Secret\n")
        .and_return(["sealed", "", ok_status])

      expect(kubeseal.send(:run, "--scope", "strict", "-o", "yaml", stdin: "kind: Secret\n"))
        .to eq("sealed")
    end

    it "passes an empty string to stdin_data when no stdin is given" do
      expect(Open3).to receive(:capture3)
        .with("kubeseal", "--fetch-cert", stdin_data: "")
        .and_return(["cert", "", ok_status])

      kubeseal.send(:run, "--fetch-cert")
    end

    it "raises CommandError carrying status, stderr, and a scrubbed command on non-zero exit" do
      allow(Open3).to receive(:capture3).and_return(["", "no controller found", fail_status])
      sealing = -> { kubeseal.send(:run, "--scope", "strict") }

      expect(&sealing).to raise_error(RKSeal::CommandError) do |error|
        expect(error.status).to eq(2)
        expect(error.stderr).to eq("no controller found")
        expect(error.command).to eq("kubeseal --scope strict")
      end
    end
  end
end
