# frozen_string_literal: true

require "base64"
require "thor"

RSpec.describe RKSeal::Commands::Edit do
  include AdapterDoubles

  subject(:command) do
    described_class.new(
      namespace: "app", name: "db", scope: scope, deploy: deploy, assume_yes: assume_yes,
      kubectl: kubectl, kubeseal: kubeseal, editor: editor,
      context_guard: context_guard, prompt: prompt,
      workspace: workspace, output_dir: output_dir
    )
  end

  let(:scope)      { nil }
  let(:deploy)     { false }
  let(:assume_yes) { false }
  # Cluster Secret: data.user is base64("alice"). rkseal shows this verbatim.
  let(:secret_json) do
    '{"apiVersion":"v1","kind":"Secret","metadata":{"name":"db","namespace":"app",' \
      '"creationTimestamp":"2024","uid":"x"},"type":"Opaque","data":{"user":"YWxpY2U="}}'
  end
  # Cluster SealedSecret (separate read) drives scope preservation. Strict here.
  let(:sealed_json) do
    '{"apiVersion":"bitnami.com/v1alpha1","kind":"SealedSecret",' \
      '"metadata":{"name":"db","namespace":"app"}}'
  end
  let(:kubectl)  { fake_kubectl(get_secret: secret_json, get_sealedsecret: sealed_json) }
  let(:sealed)   { "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\n" }
  let(:kubeseal) { fake_kubeseal(seal: sealed) }
  # By default the editor performs a real change (user -> bob via stringData).
  let(:edited_buffer) do
    <<~YAML
      apiVersion: v1
      kind: Secret
      metadata: { name: db, namespace: app }
      type: Opaque
      stringData: { user: bob }
    YAML
  end
  let(:editor)        { fake_editor(edit: edited_buffer) }
  let(:context_guard) { fake_context_guard }
  let(:prompt)        { instance_double(Thor::Shell::Basic, say: nil, yes?: true) }
  let(:workspace)     { fake_workspace }
  let(:output_dir)    { Dir.mktmpdir }

  after { FileUtils.remove_entry(output_dir) if File.directory?(output_dir) }

  def written_path = File.join(output_dir, "db.yaml")

  def b64(plain) = Base64.strict_encode64(plain)

  describe "#call" do
    it "reads the live Secret, shows base64 data in the editor, re-seals, and writes the file" do
      buffer = nil
      allow(editor).to receive(:edit) do |content:, **|
        buffer = content
        edited_buffer
      end
      command.call
      expect(YAML.safe_load(buffer).dig("data", "user")).to eq("YWxpY2U=")
      expect(File.read(written_path)).to eq(sealed)
    end

    it "shows the commented buffer header (worked stringData example) in the editor" do
      buffer = nil
      allow(editor).to receive(:edit) do |content:, **|
        buffer = content
        edited_buffer
      end
      command.call
      expect(buffer).to start_with("# rkseal:")
    end

    it "reads the cluster Secret for the right name/namespace" do
      expect(kubectl).to receive(:get_secret)
        .with(name: "db", namespace: "app").and_return(secret_json)
      command.call
    end

    it "runs the edit inside the RAM-backed workspace" do
      command.call
      expect(workspace.calls).to eq(1)
    end

    it "propagates NotFoundError (pointing at create) when the Secret is absent" do
      absent = fake_kubectl
      allow(absent).to receive(:get_secret)
        .and_raise(RKSeal::NotFoundError, "Secret app/db not found; run `rkseal create`")
      cmd = described_class.new(namespace: "app", name: "db", kubectl: absent, kubeseal: kubeseal,
                                editor: editor, workspace: workspace, output_dir: output_dir)
      expect { cmd.call }.to raise_error(RKSeal::NotFoundError, /rkseal create/)
    end

    it "returns a Result with the written path and deployed: false (default)" do
      result = command.call
      expect(result)
        .to have_attributes(output_path: File.expand_path(written_path), deployed: false)
    end

    describe "scope preservation" do
      it "preserves cluster-wide scope read from the cluster SealedSecret annotation" do
        cluster_wide = '{"kind":"SealedSecret","metadata":{"annotations":' \
                       '{"sealedsecrets.bitnami.com/cluster-wide":"true"}}}'
        allow(kubectl).to receive(:get_sealedsecret).and_return(cluster_wide)
        expect(kubeseal).to receive(:seal).with(anything, scope: :cluster_wide).and_return(sealed)
        command.call
      end

      it "defaults to strict when the cluster SealedSecret has no scope annotation" do
        expect(kubeseal).to receive(:seal).with(anything, scope: :strict).and_return(sealed)
        command.call
      end

      it "an explicit scope overrides the cluster scope" do
        cluster_wide = '{"kind":"SealedSecret","metadata":{"annotations":' \
                       '{"sealedsecrets.bitnami.com/cluster-wide":"true"}}}'
        allow(kubectl).to receive(:get_sealedsecret).and_return(cluster_wide)
        cmd = described_class.new(
          namespace: "app", name: "db", scope: :namespace_wide,
          kubectl: kubectl, kubeseal: kubeseal, editor: editor,
          context_guard: context_guard, prompt: prompt, workspace: workspace, output_dir: output_dir
        )
        expect(kubeseal).to receive(:seal).with(anything, scope: :namespace_wide).and_return(sealed)
        expect(kubectl).not_to receive(:get_sealedsecret)
        cmd.call
      end

      it "falls back to the local <name>.yaml scope when the cluster read fails" do
        File.write(written_path, <<~YAML)
          apiVersion: bitnami.com/v1alpha1
          kind: SealedSecret
          metadata:
            name: db
            namespace: app
            annotations:
              sealedsecrets.bitnami.com/namespace-wide: "true"
        YAML
        allow(kubectl).to receive(:get_sealedsecret)
          .and_raise(RKSeal::NotFoundError, "absent")
        expect(kubeseal).to receive(:seal).with(anything, scope: :namespace_wide).and_return(sealed)
        command.call
      end

      it "defaults to strict when both the cluster read and the local file are unavailable" do
        allow(kubectl).to receive(:get_sealedsecret)
          .and_raise(RKSeal::CommandError.new("unreachable"))
        expect(kubeseal).to receive(:seal).with(anything, scope: :strict).and_return(sealed)
        command.call
      end
    end

    context "when the buffer is unchanged (no-op)" do
      # Editor returns its input verbatim: the user saved without editing.
      let(:editor) { fake_editor }

      before do
        allow(editor).to receive(:edit) { |content:, **| content }
      end

      it "writes nothing and produces no fresh ciphertext" do
        expect(kubeseal).not_to receive(:seal)
        command.call
        expect(File).not_to exist(written_path)
      end

      it "does not even resolve scope (no extra cluster round-trip)" do
        expect(kubectl).not_to receive(:get_sealedsecret)
        command.call
      end

      it "returns a Result with a nil output_path and deployed: false" do
        result = command.call
        expect(result).to have_attributes(output_path: nil, deployed: false)
      end

      it "never deploys even when --deploy is set (nothing new to apply)" do
        cmd = described_class.new(namespace: "app", name: "db", deploy: true,
                                  kubectl: kubectl, kubeseal: kubeseal, editor: editor,
                                  context_guard: context_guard, prompt: prompt,
                                  workspace: workspace, output_dir: output_dir)
        expect(kubectl).not_to receive(:apply)
        expect(context_guard).not_to receive(:confirm_deploy)
        expect(cmd.call.deployed).to be(false)
      end
    end

    it "raises InvalidInputError when the saved buffer is empty" do
      allow(editor).to receive(:edit).and_return("   ")
      expect { command.call }.to raise_error(RKSeal::InvalidInputError, /empty/)
    end

    context "when deploy: false (default)" do
      it "does NOT apply or confirm the deploy" do
        expect(kubectl).not_to receive(:apply)
        expect(context_guard).not_to receive(:confirm_deploy)
        command.call
      end
    end

    context "when deploy: true" do
      let(:deploy) { true }

      it "confirms via the context guard, then applies the written file" do
        expect(context_guard).to receive(:confirm_deploy)
          .with(secret_name: "db", namespace: "app").and_return(true)
        expect(kubectl).to receive(:apply).with(file: File.expand_path(written_path))
        command.call
      end

      it "returns a Result with deployed: true after a confirmed apply" do
        expect(command.call.deployed).to be(true)
      end

      it "does NOT apply when the operator declines the confirmation" do
        allow(context_guard).to receive(:confirm_deploy).and_return(false)
        expect(kubectl).not_to receive(:apply)
        expect(command.call.deployed).to be(false)
      end

      it "still writes the file when the operator declines (deploy is the only thing skipped)" do
        allow(context_guard).to receive(:confirm_deploy).and_return(false)
        command.call
        expect(File).to exist(written_path)
      end

      it "builds a ContextGuard from kubectl and the prompt when none is injected" do
        cmd = described_class.new(namespace: "app", name: "db", deploy: true,
                                  kubectl: kubectl, kubeseal: kubeseal, editor: editor,
                                  prompt: prompt, workspace: workspace, output_dir: output_dir)
        allow(RKSeal::ContextGuard).to receive(:new)
          .with(kubectl: kubectl, prompt: prompt).and_return(context_guard)
        cmd.call
        expect(RKSeal::ContextGuard).to have_received(:new).with(kubectl: kubectl, prompt: prompt)
      end

      context "with assume_yes (--yes)" do
        let(:assume_yes) { true }

        it "skips the confirmation prompt and applies directly" do
          expect(context_guard).not_to receive(:confirm_deploy)
          expect(kubectl).to receive(:apply).with(file: File.expand_path(written_path))
          expect(command.call.deployed).to be(true)
        end
      end
    end

    context "when assume_yes is set but deploy is false" do
      let(:assume_yes) { true }

      it "does not deploy (─-yes only matters with --deploy)" do
        expect(kubectl).not_to receive(:apply)
        expect(context_guard).not_to receive(:confirm_deploy)
        expect(command.call.deployed).to be(false)
      end
    end
  end
end
