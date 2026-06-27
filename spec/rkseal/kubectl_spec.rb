# frozen_string_literal: true

RSpec.describe RKSeal::Kubectl do
  subject(:kubectl) { described_class.new(binary: "kubectl") }

  # Stub the single shell-out seam, capturing the argv/stdin for assertions.
  def stub_run(returning: "")
    captured = {}
    allow(kubectl).to receive(:run) do |*argv, **kwargs|
      captured[:argv] = argv
      captured[:stdin] = kwargs[:stdin]
      returning
    end
    captured
  end

  # Build the CommandError the real runner would raise for a given stderr, so we
  # can drive the NotFound-vs-CommandError branching without spawning kubectl.
  def command_error(stderr:, status: 1)
    RKSeal::CommandError.new(
      "kubectl failed (exit #{status}): #{stderr}",
      command: "kubectl get secret db -n app -o json",
      status: status,
      stderr: stderr
    )
  end

  describe "#ensure_available!" do
    it "raises DependencyMissingError when kubectl is not on PATH" do
      adapter = described_class.new(binary: "kubectl-does-not-exist-xyz")
      allow(adapter).to receive(:executable_on_path?).and_return(false)

      expect { adapter.ensure_available! }
        .to raise_error(RKSeal::DependencyMissingError, /kubectl not found on PATH/)
    end

    it "does not raise when the binary is resolvable" do
      allow(kubectl).to receive(:executable_on_path?).and_return(true)

      expect { kubectl.ensure_available! }.not_to raise_error
    end
  end

  describe "#get_secret" do
    it "runs `kubectl get secret <name> -n <ns> -o json` and returns the JSON" do
      captured = stub_run(returning: %({"kind":"Secret"}))

      result = kubectl.get_secret(name: "db", namespace: "app")

      expect(captured[:argv]).to eq(%w[get secret db -n app -o json])
      expect(result).to eq(%({"kind":"Secret"}))
    end

    it "raises NotFoundError pointing at `rkseal create` when the Secret does not exist" do
      allow(kubectl).to receive(:run)
        .and_raise(command_error(stderr: %(Error from server (NotFound): secrets "db" not found)))

      expect { kubectl.get_secret(name: "db", namespace: "app") }
        .to raise_error(RKSeal::NotFoundError) do |error|
          expect(error.message).to include("rkseal create app db")
          expect(error.message).to include("db")
          expect(error.message).to include("app")
        end
    end

    it "is case-insensitive when detecting NotFound" do
      allow(kubectl).to receive(:run)
        .and_raise(command_error(stderr: "some NOTFOUND condition"))

      expect { kubectl.get_secret(name: "db", namespace: "app") }
        .to raise_error(RKSeal::NotFoundError)
    end

    it "raises CommandError on other failures (cluster unreachable, unknown namespace)" do
      allow(kubectl).to receive(:run)
        .and_raise(command_error(stderr: "The connection to the server was refused"))

      expect { kubectl.get_secret(name: "db", namespace: "app") }
        .to raise_error(RKSeal::CommandError, /connection to the server was refused/)
    end
  end

  describe "#get_sealedsecret" do
    it "runs `kubectl get sealedsecret <name> -n <ns> -o json` and returns the JSON" do
      captured = stub_run(returning: %({"kind":"SealedSecret"}))

      result = kubectl.get_sealedsecret(name: "db", namespace: "app")

      expect(captured[:argv]).to eq(%w[get sealedsecret db -n app -o json])
      expect(result).to eq(%({"kind":"SealedSecret"}))
    end

    it "raises NotFoundError when the SealedSecret does not exist" do
      stderr = %(Error from server (NotFound): sealedsecrets "db" not found)
      allow(kubectl).to receive(:run).and_raise(command_error(stderr: stderr))

      expect { kubectl.get_sealedsecret(name: "db", namespace: "app") }
        .to raise_error(RKSeal::NotFoundError, /SealedSecret "db" not found in namespace "app"/)
    end

    it "raises CommandError on other failures (e.g. CRD not installed, cluster unreachable)" do
      stderr = %(error: the server doesn't have a resource type "sealedsecret")
      allow(kubectl).to receive(:run).and_raise(command_error(stderr: stderr))

      expect { kubectl.get_sealedsecret(name: "db", namespace: "app") }
        .to raise_error(RKSeal::CommandError, /doesn't have a resource type/)
    end
  end

  describe "#list_sealedsecrets" do
    it "scopes to one namespace with -n when a namespace is given" do
      captured = stub_run(returning: %({"items":[]}))

      result = kubectl.list_sealedsecrets(namespace: "app")

      expect(captured[:argv]).to eq(%w[get sealedsecret -n app -o json])
      expect(result).to eq(%({"items":[]}))
    end

    it "lists across all namespaces with -A when namespace is nil" do
      captured = stub_run(returning: %({"items":[]}))

      result = kubectl.list_sealedsecrets

      expect(captured[:argv]).to eq(%w[get sealedsecret -A -o json])
      expect(result).to eq(%({"items":[]}))
    end

    it "returns an empty list normally (empty items is not an error)" do
      allow(kubectl).to receive(:run).and_return(%({"apiVersion":"v1","kind":"List","items":[]}))

      expect { kubectl.list_sealedsecrets(namespace: "empty-ns") }.not_to raise_error
      expect(kubectl.list_sealedsecrets(namespace: "empty-ns")).to include(%("items":[]))
    end

    it "raises CommandError on failure (e.g. CRD absent, cluster unreachable)" do
      stderr = %(error: the server doesn't have a resource type "sealedsecret")
      allow(kubectl).to receive(:run).and_raise(command_error(stderr: stderr))

      expect { kubectl.list_sealedsecrets }
        .to raise_error(RKSeal::CommandError, /doesn't have a resource type/)
    end
  end

  describe "#apply" do
    it "runs `kubectl apply -f <file>` and returns stdout" do
      captured = stub_run(returning: "sealedsecret.bitnami.com/db configured")

      result = kubectl.apply(file: "db.yaml")

      expect(captured[:argv]).to eq(%w[apply -f db.yaml])
      expect(result).to eq("sealedsecret.bitnami.com/db configured")
    end

    it "raises CommandError when apply fails" do
      allow(kubectl).to receive(:run)
        .and_raise(command_error(stderr: "error validating data", status: 1))

      expect { kubectl.apply(file: "db.yaml") }
        .to raise_error(RKSeal::CommandError, /error validating data/)
    end
  end

  describe "#current_context" do
    it "returns the active context name, whitespace stripped" do
      captured = stub_run(returning: "docker-desktop\n")

      result = kubectl.current_context

      expect(captured[:argv]).to eq(%w[config current-context])
      expect(result).to eq("docker-desktop")
    end
  end

  # The runner itself: driven through a stubbed Open3 so no real kubectl runs.
  describe "#run (private seam)", :allow_exec do
    let(:ok_status) { instance_double(Process::Status, success?: true, exitstatus: 0) }
    let(:fail_status) { instance_double(Process::Status, success?: false, exitstatus: 1) }

    it "invokes Open3.capture3 with an argv array (no shell string)" do
      expect(Open3).to receive(:capture3)
        .with("kubectl", "get", "secret", "db", "-n", "app", "-o", "json", stdin_data: "")
        .and_return([%({}), "", ok_status])

      expect(kubectl.send(:run, "get", "secret", "db", "-n", "app", "-o", "json")).to eq(%({}))
    end

    it "raises CommandError carrying status, stderr, and a scrubbed command on non-zero exit" do
      allow(Open3).to receive(:capture3).and_return(["", "boom", fail_status])
      applying = -> { kubectl.send(:run, "apply", "-f", "db.yaml") }

      expect(&applying).to raise_error(RKSeal::CommandError) do |error|
        expect(error.status).to eq(1)
        expect(error.stderr).to eq("boom")
        expect(error.command).to eq("kubectl apply -f db.yaml")
      end
    end
  end
end
