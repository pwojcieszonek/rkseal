# frozen_string_literal: true

require "thor"

RSpec.describe RKSeal::ContextGuard do
  include AdapterDoubles

  subject(:guard) { described_class.new(kubectl: kubectl, prompt: prompt) }

  let(:kubectl) { fake_kubectl(current_context: "docker-desktop") }
  let(:prompt) { instance_double(Thor::Shell::Basic, yes?: false) }

  describe "#current_context" do
    it "returns the active context from kubectl" do
      expect(guard.current_context).to eq("docker-desktop")
      expect(kubectl).to have_received(:current_context)
    end
  end

  describe "#confirm_deploy" do
    it "asks the operator, naming the secret, namespace, and active context" do
      allow(prompt).to receive(:yes?).and_return(true)

      result = guard.confirm_deploy(secret_name: "db", namespace: "app")

      expect(prompt).to have_received(:yes?)
        .with(%(Deploy "db" (namespace "app") to context "docker-desktop"? [y/N]))
      expect(result).to be(true)
    end

    it "returns true when the operator confirms" do
      allow(prompt).to receive(:yes?).and_return(true)

      expect(guard.confirm_deploy(secret_name: "db", namespace: "app")).to be(true)
    end

    it "returns false when the operator declines (the default)" do
      allow(prompt).to receive(:yes?).and_return(false)

      expect(guard.confirm_deploy(secret_name: "db", namespace: "app")).to be(false)
    end

    it "reflects the live context in the prompt" do
      other = described_class.new(
        kubectl: fake_kubectl(current_context: "tkk-k0s-prod"),
        prompt: prompt
      )
      allow(prompt).to receive(:yes?).and_return(false)

      other.confirm_deploy(secret_name: "db", namespace: "app")

      expect(prompt).to have_received(:yes?).with(/context "tkk-k0s-prod"/)
    end

    it "defaults the prompt to a real Thor shell when none is injected" do
      bare = described_class.new(kubectl: kubectl)
      shell = bare.instance_variable_get(:@prompt)

      expect(shell).to be_a(Thor::Shell::Basic)
    end
  end
end
