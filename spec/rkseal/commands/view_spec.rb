# frozen_string_literal: true

require "base64"
require "json"

RSpec.describe RKSeal::Commands::View do
  include AdapterDoubles

  subject(:command) do
    described_class.new(namespace: "app", name: "db", reveal: reveal, kubectl: kubectl)
  end

  let(:reveal) { false }
  let(:secret_json) do
    {
      "apiVersion" => "v1", "kind" => "Secret",
      "metadata" => { "name" => "db", "namespace" => "app", "uid" => "x" },
      "type" => "Opaque",
      "data" => { "user" => Base64.strict_encode64("alice") }
    }.to_json
  end
  let(:kubectl) { fake_kubectl(get_secret: secret_json) }

  describe "#call" do
    it "reads the live Secret for the right name/namespace" do
      expect(kubectl).to receive(:get_secret)
        .with(name: "db", namespace: "app").and_return(secret_json)
      command.call
    end

    it "renders the full Secret manifest" do
      doc = YAML.safe_load(command.call)
      expect(doc).to include("apiVersion" => "v1", "kind" => "Secret", "type" => "Opaque")
      expect(doc.dig("metadata", "name")).to eq("db")
    end

    it "shows data as raw base64 by default (never decoded)" do
      doc = YAML.safe_load(command.call)
      expect(doc.fetch("data")).to eq("user" => Base64.strict_encode64("alice"))
      expect(command.call).not_to include("alice")
    end

    context "with reveal: true" do
      let(:reveal) { true }

      it "decodes data and presents values as plaintext stringData" do
        doc = YAML.safe_load(command.call)
        expect(doc.fetch("stringData")).to eq("user" => "alice")
        expect(doc).not_to have_key("data")
      end
    end

    it "is read-only: it never applies, seals, or writes (only get_secret is used)" do
      expect(kubectl).to receive(:get_secret).and_return(secret_json)
      expect(kubectl).not_to receive(:apply)
      command.call
    end

    it "propagates NotFoundError (pointing at create) when the Secret is absent" do
      absent = fake_kubectl
      allow(absent).to receive(:get_secret)
        .and_raise(RKSeal::NotFoundError, "Secret app/db not found; run `rkseal create`")
      cmd = described_class.new(namespace: "app", name: "db", kubectl: absent)
      expect { cmd.call }.to raise_error(RKSeal::NotFoundError, /rkseal create/)
    end
  end
end
