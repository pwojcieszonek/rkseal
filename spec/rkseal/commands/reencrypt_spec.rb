# frozen_string_literal: true

require "thor"

RSpec.describe RKSeal::Commands::Reencrypt do
  include AdapterDoubles

  subject(:command) do
    described_class.new(
      namespace: "app", name: "db", deploy: deploy, assume_yes: assume_yes,
      kubectl: kubectl, kubeseal: kubeseal,
      context_guard: context_guard, prompt: prompt, output_dir: output_dir
    )
  end

  let(:deploy)     { false }
  let(:assume_yes) { false }
  let(:reencrypted) { "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\n# re-encrypted\n" }
  let(:kubectl)  { fake_kubectl }
  let(:kubeseal) { fake_kubeseal(re_encrypt: reencrypted) }
  let(:context_guard) { fake_context_guard }
  let(:prompt)        { instance_double(Thor::Shell::Basic, say: nil, yes?: true) }
  let(:output_dir)    { Dir.mktmpdir }

  after { FileUtils.remove_entry(output_dir) if File.directory?(output_dir) }

  def written_path = File.join(output_dir, "db.yaml")

  describe "#call" do
    context "when a local <name>.yaml exists" do
      before { File.write(written_path, "kind: SealedSecret\n# original\n") }

      it "re-encrypts the local file and writes the result back to <name>.yaml" do
        expect(kubeseal).to receive(:re_encrypt).with("kind: SealedSecret\n# original\n")
                                                .and_return(reencrypted)
        command.call
        expect(File.read(written_path)).to eq(reencrypted)
      end

      it "does not read the cluster SealedSecret when the local file is present" do
        expect(kubectl).not_to receive(:get_sealedsecret)
        command.call
      end

      it "returns a Result with the written path and deployed: false (default)" do
        result = command.call
        expect(result)
          .to have_attributes(output_path: File.expand_path(written_path), deployed: false)
      end
    end

    context "when no local file exists" do
      it "falls back to the cluster SealedSecret" do
        expect(kubectl).to receive(:get_sealedsecret)
          .with(name: "db", namespace: "app").and_return("kind: SealedSecret\n# cluster\n")
        expect(kubeseal).to receive(:re_encrypt).with("kind: SealedSecret\n# cluster\n")
                                                .and_return(reencrypted)
        command.call
        expect(File.read(written_path)).to eq(reencrypted)
      end

      it "fails fast pointing at create when the SealedSecret is also absent" do
        allow(kubectl).to receive(:get_sealedsecret)
          .and_raise(RKSeal::NotFoundError, "absent")
        expect(kubeseal).not_to receive(:re_encrypt)
        expect { command.call }
          .to raise_error(RKSeal::NotFoundError, /rkseal create/)
      end
    end

    context "when deploy: true" do
      let(:deploy) { true }

      before { File.write(written_path, "kind: SealedSecret\n") }

      it "confirms via the context guard, then applies the written file" do
        expect(context_guard).to receive(:confirm_deploy)
          .with(secret_name: "db", namespace: "app").and_return(true)
        expect(kubectl).to receive(:apply).with(file: File.expand_path(written_path))
        expect(command.call.deployed).to be(true)
      end

      it "does NOT apply when the operator declines" do
        allow(context_guard).to receive(:confirm_deploy).and_return(false)
        expect(kubectl).not_to receive(:apply)
        expect(command.call.deployed).to be(false)
      end

      context "with assume_yes" do
        let(:assume_yes) { true }

        it "skips the prompt and applies directly" do
          expect(context_guard).not_to receive(:confirm_deploy)
          expect(kubectl).to receive(:apply).with(file: File.expand_path(written_path))
          expect(command.call.deployed).to be(true)
        end
      end

      it "builds a ContextGuard from kubectl and prompt when none is injected" do
        cmd = described_class.new(namespace: "app", name: "db", deploy: true,
                                  kubectl: kubectl, kubeseal: kubeseal,
                                  prompt: prompt, output_dir: output_dir)
        allow(RKSeal::ContextGuard).to receive(:new)
          .with(kubectl: kubectl, prompt: prompt).and_return(context_guard)
        cmd.call
        expect(RKSeal::ContextGuard).to have_received(:new).with(kubectl: kubectl, prompt: prompt)
      end
    end

    context "when deploy: false (default)" do
      before { File.write(written_path, "kind: SealedSecret\n") }

      it "does NOT apply or confirm" do
        expect(kubectl).not_to receive(:apply)
        expect(context_guard).not_to receive(:confirm_deploy)
        command.call
      end
    end
  end
end
