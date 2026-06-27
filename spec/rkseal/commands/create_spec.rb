# frozen_string_literal: true

require "base64"

RSpec.describe RKSeal::Commands::Create do
  include AdapterDoubles

  subject(:command) do
    described_class.new(
      namespace: "app", name: "db", scope: scope,
      type: type, from_file: from_file, no_edit: no_edit,
      kubeseal: kubeseal, editor: editor, workspace: workspace, output_dir: output_dir
    )
  end

  let(:scope)     { :strict }
  let(:type)      { "Opaque" }
  let(:from_file) { nil }
  let(:no_edit)   { false }
  let(:sealed)    { "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\n" }
  let(:kubeseal)  { fake_kubeseal(seal: sealed) }
  let(:edited_secret_yaml) do
    <<~YAML
      apiVersion: v1
      kind: Secret
      metadata: { name: db, namespace: app }
      stringData: { user: alice }
    YAML
  end
  let(:editor)     { fake_editor(edit: edited_secret_yaml) }
  let(:workspace)  { fake_workspace }
  let(:output_dir) { Dir.mktmpdir }

  after { FileUtils.remove_entry(output_dir) if File.directory?(output_dir) }

  def written_path = File.join(output_dir, "db.yaml")

  def b64(plain) = Base64.strict_encode64(plain)

  describe "#call" do
    it "seeds a template, edits it, seals it, and writes <name>.yaml to the output dir" do
      command.call
      expect(File.read(written_path)).to eq(sealed)
    end

    it "checks the kubeseal dependency is available before doing work" do
      expect(kubeseal).to receive(:ensure_available!)
      command.call
    end

    it "pre-resolves the controller cert before opening the editor (fail fast)" do
      expect(kubeseal).to receive(:ensure_cert!).ordered
      expect(editor).to receive(:edit).ordered.and_return(edited_secret_yaml)
      command.call
    end

    it "does not open the editor when cert resolution fails" do
      allow(kubeseal).to receive(:ensure_cert!)
        .and_raise(RKSeal::CommandError.new("controller unreachable"))
      expect(editor).not_to receive(:edit)
      expect { command.call }.to raise_error(RKSeal::CommandError, /unreachable/)
    end

    it "seeds the editor buffer with a commented Secret skeleton for the right name/namespace" do
      buffer = nil
      allow(editor).to receive(:edit) do |content:, **|
        buffer = content
        edited_secret_yaml
      end
      command.call
      expect(buffer).to start_with("# rkseal:")
      expect(YAML.safe_load(buffer).dig("metadata", "name")).to eq("db")
    end

    it "runs the edit inside the RAM-backed workspace (no plaintext on disk)" do
      command.call
      expect(workspace.calls).to eq(1)
      expect(workspace.last_basename).to eq("db")
    end

    it "edits the buffer on the path the workspace provides" do
      workspace_path = File.join(output_dir, "buffer-path")
      ws = fake_workspace(path: workspace_path)
      allow(editor).to receive(:edit).and_return(edited_secret_yaml)
      described_class.new(namespace: "app", name: "db", kubeseal: kubeseal, editor: editor,
                          workspace: ws, output_dir: output_dir).call
      expect(editor).to have_received(:edit).with(hash_including(path: workspace_path))
    end

    it "passes the parsed Secret manifest and chosen scope through to kubeseal" do
      command_with_scope = described_class.new(
        namespace: "app", name: "db", scope: :cluster_wide,
        kubeseal: kubeseal, editor: editor, workspace: workspace, output_dir: output_dir
      )
      expect(kubeseal).to receive(:seal) do |manifest, scope:|
        expect(scope).to eq(:cluster_wide)
        expect(YAML.safe_load(manifest).fetch("data")).to eq("user" => b64("alice"))
        sealed
      end
      command_with_scope.call
    end

    it "returns a Result with the absolute output path and deployed: false" do
      result = command.call
      expect(result).to have_attributes(
        secret_name: "db", namespace: "app",
        output_path: File.expand_path(written_path), deployed: false
      )
    end

    it "raises InvalidInputError on an empty edit buffer (and writes nothing)" do
      allow(editor).to receive(:edit)
        .and_return("apiVersion: v1\nkind: Secret\nmetadata: { name: db, namespace: app }\n")
      expect { command.call }.to raise_error(RKSeal::InvalidInputError, /no data items/)
      expect(File).not_to exist(written_path)
    end

    it "raises InvalidInputError on malformed YAML from the editor" do
      allow(editor).to receive(:edit).and_return("data: [unterminated")
      expect { command.call }.to raise_error(RKSeal::InvalidInputError, /not valid YAML/)
    end

    it "does not seal when the buffer is invalid" do
      allow(editor).to receive(:edit).and_return("just a string")
      expect(kubeseal).not_to receive(:seal)
      expect { command.call }.to raise_error(RKSeal::InvalidInputError)
    end

    context "with --from-file" do
      let(:source) { File.join(output_dir, "cert.pem") }
      let(:from_file) { { "cert" => source } }

      before { File.binwrite(source, "PEM-BYTES") }

      it "pre-seeds the file's contents (base64) into the buffer before editing" do
        buffer = nil
        allow(editor).to receive(:edit) do |content:, **|
          buffer = content
          content
        end
        command.call
        expect(YAML.safe_load(buffer).dig("data", "cert")).to eq(b64("PEM-BYTES"))
      end

      it "raises InvalidInputError when a --from-file path does not exist" do
        bad = described_class.new(
          namespace: "app", name: "db", from_file: { "x" => "/no/such/file" },
          kubeseal: kubeseal, editor: editor, workspace: workspace, output_dir: output_dir
        )
        expect { bad.call }
          .to raise_error(RKSeal::InvalidInputError, %r{--from-file x=/no/such/file})
      end
    end

    context "with --no-edit" do
      let(:no_edit)   { true }
      let(:source)    { File.join(output_dir, "blob.bin") }
      let(:from_file) { { "tls.crt" => source } }
      let(:payload)   { "binary\x00payload" }

      before { File.binwrite(source, payload) }

      it "seals the pre-seeded Secret directly without opening the editor" do
        expect(editor).not_to receive(:edit)
        expect(workspace).not_to receive(:with)
        command.call
        expect(File.read(written_path)).to eq(sealed)
      end

      it "seals the base64-encoded file contents" do
        expect(kubeseal).to receive(:seal) do |manifest, **|
          expect(YAML.safe_load(manifest).dig("data", "tls.crt")).to eq(b64(payload))
          sealed
        end
        command.call
      end

      it "still fails fast on an empty Secret (no data and no --from-file)" do
        empty = described_class.new(
          namespace: "app", name: "db", no_edit: true,
          kubeseal: kubeseal, editor: editor, workspace: workspace, output_dir: output_dir
        )
        expect { empty.call }.to raise_error(RKSeal::InvalidInputError, /no data items/)
      end
    end

    context "with a typed Secret (kubernetes.io/tls)" do
      let(:type) { "kubernetes.io/tls" }

      it "fails fast when required keys are missing after editing" do
        allow(editor).to receive(:edit).and_return(
          "apiVersion: v1\nkind: Secret\nmetadata: { name: db, namespace: app }\n" \
          "type: kubernetes.io/tls\nstringData: { tls.crt: only-cert }\n"
        )
        expect { command.call }.to raise_error(RKSeal::InvalidInputError, /tls\.key/)
      end
    end
  end
end
