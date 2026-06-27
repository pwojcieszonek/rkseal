# frozen_string_literal: true

require "json"
require "time"

RSpec.describe RKSeal::Commands::List do
  include AdapterDoubles

  let(:now) { Time.parse("2026-06-27T00:00:00Z") }
  let(:kubectl) { fake_kubectl(list_sealedsecrets: list_json) }

  def item(name:, namespace:, scope: nil, created: nil, encrypted: nil)
    annotations =
      case scope
      when :cluster_wide then { "sealedsecrets.bitnami.com/cluster-wide" => "true" }
      when :namespace_wide then { "sealedsecrets.bitnami.com/namespace-wide" => "true" }
      end
    metadata = { "name" => name, "namespace" => namespace }
    metadata["annotations"] = annotations if annotations
    metadata["creationTimestamp"] = created if created
    { "metadata" => metadata,
      "spec" => { "encryptedData" => encrypted || { "k" => "AgBSECRET==" } } }
  end

  def list_doc(*items) = { "items" => items }.to_json

  describe "#call" do
    context "with several SealedSecrets across namespaces" do
      let(:list_json) do
        list_doc(
          item(name: "db", namespace: "app", created: "2026-06-24T00:00:00Z"),
          item(name: "tls", namespace: "web", scope: :cluster_wide,
               created: "2026-06-26T22:00:00Z"),
          item(name: "api", namespace: "web", scope: :namespace_wide,
               created: "2026-06-26T23:59:30Z")
        )
      end

      subject(:output) { described_class.new(kubectl: kubectl, now: now).call }

      it "prints a header row with NAMESPACE, NAME, SCOPE, AGE" do
        expect(output.lines.first).to match(/\ANAMESPACE\s+NAME\s+SCOPE\s+AGE\s*\z/)
      end

      it "renders one row per item with the right namespace and name" do
        expect(output).to match(/^app\s+db\s/)
        expect(output).to match(/^web\s+tls\s/)
        expect(output).to match(/^web\s+api\s/)
      end

      it "derives the SCOPE column from each item's annotation" do
        expect(output).to match(/db\s+strict\s/)
        expect(output).to match(/tls\s+cluster-wide\s/)
        expect(output).to match(/api\s+namespace-wide\s/)
      end

      it "shows a compact kubectl-style AGE from creationTimestamp" do
        expect(output).to match(/db\s+strict\s+3d$/)
        expect(output).to match(/tls\s+cluster-wide\s+2h$/)
        expect(output).to match(/api\s+namespace-wide\s+30s$/)
      end

      it "has no trailing whitespace on any line" do
        expect(output.lines.map(&:chomp)).to all(satisfy { |line| line == line.rstrip })
      end
    end

    context "metadata-only guarantee (no value leak)" do
      let(:list_json) do
        list_doc(
          item(name: "db", namespace: "app", created: "2026-06-26T00:00:00Z",
               encrypted: { "password" => "AgBVERYSECRETCIPHERTEXT==" })
        )
      end

      subject(:output) { described_class.new(kubectl: kubectl, now: now).call }

      it "never prints any encryptedData value" do
        expect(output).not_to include("AgBVERYSECRETCIPHERTEXT")
      end

      it "never prints encryptedData key names either" do
        expect(output).not_to include("password")
      end
    end

    context "with a missing creationTimestamp" do
      let(:list_json) { list_doc(item(name: "x", namespace: "app")) }

      it "shows <unknown> for AGE rather than raising" do
        expect(described_class.new(kubectl: kubectl, now: now).call)
          .to match(/x\s+strict\s+<unknown>$/)
      end
    end

    context "when the list is empty" do
      let(:list_json) { list_doc }

      it "prints a friendly all-namespaces message" do
        expect(described_class.new(kubectl: kubectl).call).to eq("No SealedSecrets found.")
      end

      it "names the namespace when one was given" do
        expect(described_class.new(namespace: "app", kubectl: kubectl).call)
          .to eq('No SealedSecrets found in namespace "app".')
      end
    end

    describe "namespace passthrough" do
      let(:list_json) { list_doc }

      it "passes nil to list_sealedsecrets when no namespace is given (all namespaces)" do
        expect(kubectl).to receive(:list_sealedsecrets).with(namespace: nil).and_return(list_json)
        described_class.new(kubectl: kubectl).call
      end

      it "passes the namespace through when given" do
        expect(kubectl).to receive(:list_sealedsecrets).with(namespace: "app").and_return(list_json)
        described_class.new(namespace: "app", kubectl: kubectl).call
      end
    end

    context "operational behaviour" do
      let(:list_json) do
        list_doc(item(name: "db", namespace: "app", created: "2026-06-26T00:00:00Z"))
      end

      it "checks the kubectl dependency is available" do
        expect(kubectl).to receive(:ensure_available!)
        described_class.new(kubectl: kubectl).call
      end

      it "is read-only: it never applies or writes (only list_sealedsecrets is used)" do
        expect(kubectl).not_to receive(:apply)
        described_class.new(kubectl: kubectl).call
      end

      it "raises CommandError on malformed JSON from kubectl" do
        bad = fake_kubectl(list_sealedsecrets: "{ not json")
        expect { described_class.new(kubectl: bad).call }
          .to raise_error(RKSeal::CommandError, /valid JSON/)
      end
    end
  end
end
