# frozen_string_literal: true

require "thor"

RSpec.describe RKSeal::Commands::EditLocal do
  include AdapterDoubles

  subject(:command) do
    described_class.new(
      namespace: "app", name: "db", deploy: deploy, assume_yes: assume_yes,
      kubectl: kubectl, kubeseal: kubeseal, editor: editor,
      context_guard: context_guard, prompt: prompt,
      workspace: workspace, output_dir: output_dir
    )
  end

  let(:deploy)     { false }
  let(:assume_yes) { false }
  let(:kubectl)    { fake_kubectl }
  let(:kubeseal)   { fake_kubeseal }
  let(:editor)     { fake_editor(edit: edited_buffer) }
  let(:context_guard) { fake_context_guard }
  let(:prompt)        { instance_double(Thor::Shell::Basic, say: nil, yes?: true) }
  let(:workspace)     { fake_workspace }
  let(:output_dir)    { Dir.mktmpdir }

  let(:local_sealed) do
    <<~YAML
      apiVersion: bitnami.com/v1alpha1
      kind: SealedSecret
      metadata:
        name: db
        namespace: app
      spec:
        encryptedData:
          password: AgApassword
          username: AgAusername
        template:
          metadata:
            name: db
            namespace: app
          type: Opaque
    YAML
  end

  # Default buffer: keep everything (both keys left redacted) -> a no-op.
  let(:edited_buffer) do
    <<~YAML
      apiVersion: v1
      kind: Secret
      metadata: { name: db, namespace: app }
      type: Opaque
      stringData:
        password: <redacted>
        username: <redacted>
    YAML
  end

  def written_path = File.join(output_dir, "db.yaml")
  def write_local! = File.write(written_path, local_sealed)

  after { FileUtils.remove_entry(output_dir) if File.directory?(output_dir) }

  describe "#call" do
    context "when no local <name>.yaml exists" do
      it "fails fast pointing at create, without opening the editor" do
        expect(editor).not_to receive(:edit)
        expect { command.call }
          .to raise_error(RKSeal::NotFoundError, /rkseal create app db/)
      end
    end

    context "with a local file present" do
      before { write_local! }

      it "never reads cluster state (offline by design)" do
        expect(kubectl).not_to receive(:get_secret)
        expect(kubectl).not_to receive(:get_sealedsecret)
        command.call
      end

      it "seeds the editor with a redacted buffer under data (base64) by default" do
        expect(editor).to receive(:edit) do |content:, **|
          doc = YAML.safe_load(content)
          expect(doc["data"]).to eq("password" => "<redacted>", "username" => "<redacted>")
          expect(doc).not_to have_key("stringData")
          edited_buffer
        end
        command.call
      end

      context "with string_data: true" do
        subject(:command) do
          described_class.new(
            namespace: "app", name: "db", string_data: true,
            kubectl: kubectl, kubeseal: kubeseal, editor: editor,
            context_guard: context_guard, prompt: prompt,
            workspace: workspace, output_dir: output_dir
          )
        end

        it "seeds the redacted buffer under stringData (plaintext)" do
          expect(editor).to receive(:edit) do |content:, **|
            doc = YAML.safe_load(content)
            expect(doc["stringData"]).to eq("password" => "<redacted>", "username" => "<redacted>")
            expect(doc).not_to have_key("data")
            edited_buffer
          end
          command.call
        end
      end

      context "when everything is kept (no-op)" do
        it "writes nothing, reseals nothing, and reports a nil output_path" do
          expect(kubeseal).not_to receive(:merge_into)
          expect(kubeseal).not_to receive(:ensure_cert!)
          result = command.call
          expect(result).to have_attributes(output_path: nil, deployed: false)
          expect(File.read(written_path)).to eq(local_sealed)
        end
      end

      context "when a value is replaced" do
        let(:edited_buffer) do
          <<~YAML
            apiVersion: v1
            kind: Secret
            metadata: { name: db, namespace: app }
            type: Opaque
            stringData:
              password: new-secret
              username: <redacted>
          YAML
        end

        it "reseals only the changed key via merge_into (kept key untouched)" do
          expect(kubeseal).to receive(:ensure_cert!)
          expect(kubeseal).to receive(:merge_into) do |manifest, file:, scope:|
            doc = YAML.safe_load(manifest)
            expect(doc["data"]).to eq("password" => Base64.strict_encode64("new-secret"))
            expect(file).to eq(File.expand_path(written_path))
            expect(scope).to eq(:strict)
          end
          expect(command.call.output_path).to eq(File.expand_path(written_path))
        end
      end

      context "when a value is replaced under the data block (base64)" do
        let(:edited_buffer) do
          <<~YAML
            apiVersion: v1
            kind: Secret
            metadata: { name: db, namespace: app }
            type: Opaque
            data:
              password: <redacted>
              username: #{Base64.strict_encode64("bob")}
          YAML
        end

        it "honours the placeholder under data and reseals the base64 value" do
          expect(kubeseal).to receive(:merge_into) do |manifest, **|
            # password kept (placeholder), only username resealed verbatim base64
            expect(YAML.safe_load(manifest)["data"])
              .to eq("username" => Base64.strict_encode64("bob"))
          end
          command.call
        end
      end

      context "when a new key is added" do
        let(:edited_buffer) do
          <<~YAML
            apiVersion: v1
            kind: Secret
            metadata: { name: db, namespace: app }
            type: Opaque
            stringData:
              password: <redacted>
              username: <redacted>
              apikey: brand-new
          YAML
        end

        it "seals the new key via merge_into" do
          expect(kubeseal).to receive(:merge_into) do |manifest, **|
            expect(YAML.safe_load(manifest)["data"])
              .to eq("apikey" => Base64.strict_encode64("brand-new"))
          end
          command.call
        end
      end

      context "when a key is removed" do
        let(:edited_buffer) do
          <<~YAML
            apiVersion: v1
            kind: Secret
            metadata: { name: db, namespace: app }
            type: Opaque
            stringData:
              password: <redacted>
          YAML
        end

        it "drops it from encryptedData without redoing any ciphertext" do
          expect(kubeseal).not_to receive(:merge_into)
          expect(kubeseal).not_to receive(:ensure_cert!)
          command.call
          enc = YAML.safe_load_file(written_path).dig("spec", "encryptedData")
          expect(enc).to eq("password" => "AgApassword")
        end
      end

      context "when the type is changed" do
        let(:edited_buffer) do
          <<~YAML
            apiVersion: v1
            kind: Secret
            metadata: { name: db, namespace: app }
            type: kubernetes.io/basic-auth
            stringData:
              password: <redacted>
              username: <redacted>
          YAML
        end

        it "updates spec.template.type and reseals nothing" do
          expect(kubeseal).not_to receive(:merge_into)
          command.call
          expect(YAML.safe_load_file(written_path).dig("spec", "template", "type"))
            .to eq("kubernetes.io/basic-auth")
        end
      end

      context "when the scope is non-strict" do
        let(:local_sealed) do
          <<~YAML
            apiVersion: bitnami.com/v1alpha1
            kind: SealedSecret
            metadata:
              name: db
              namespace: app
              annotations:
                sealedsecrets.bitnami.com/namespace-wide: "true"
            spec:
              encryptedData: { password: AgApassword }
              template: { type: Opaque }
          YAML
        end
        let(:edited_buffer) do
          "apiVersion: v1\nkind: Secret\nmetadata: { name: db, namespace: app }\n" \
            "type: Opaque\nstringData: { password: rotated }\n"
        end

        it "preserves the existing scope when resealing" do
          expect(kubeseal).to receive(:merge_into).with(anything, file: anything,
                                                                  scope: :namespace_wide)
          command.call
        end
      end

      describe "validation (fail fast)" do
        context "with an empty buffer" do
          let(:edited_buffer) { "" }

          it "raises InvalidInputError" do
            expect { command.call }.to raise_error(RKSeal::InvalidInputError, /empty/)
          end
        end

        context "when a new key is left as the placeholder" do
          let(:edited_buffer) do
            "apiVersion: v1\nkind: Secret\nmetadata: { name: db, namespace: app }\n" \
              "type: Opaque\nstringData: { password: <redacted>, username: <redacted>, " \
              "newone: <redacted> }\n"
          end

          it "raises so an empty new key is never silently dropped" do
            expect { command.call }
              .to raise_error(RKSeal::InvalidInputError, /placeholder/)
          end
        end

        context "when a value is blank" do
          let(:edited_buffer) do
            "apiVersion: v1\nkind: Secret\nmetadata: { name: db, namespace: app }\n" \
              "type: Opaque\nstringData: { password: '', username: <redacted> }\n"
          end

          it "raises rather than sealing an empty value" do
            expect { command.call }
              .to raise_error(RKSeal::InvalidInputError, /empty value/)
          end
        end

        context "when the buffer renames the secret" do
          let(:edited_buffer) do
            "apiVersion: v1\nkind: Secret\nmetadata: { name: renamed, namespace: app }\n" \
              "type: Opaque\nstringData: { password: x }\n"
          end

          it "refuses, since strict ciphertext binds name/namespace" do
            expect { command.call }
              .to raise_error(RKSeal::InvalidInputError, /cannot rename or move/)
          end
        end

        context "when every key is removed" do
          let(:edited_buffer) do
            "apiVersion: v1\nkind: Secret\nmetadata: { name: db, namespace: app }\n" \
              "type: Opaque\nstringData: {}\n"
          end

          it "refuses to leave the SealedSecret empty" do
            expect { command.call }
              .to raise_error(RKSeal::InvalidInputError, /no data items/)
          end
        end
      end

      context "with deploy: true (after a change)" do
        let(:deploy) { true }
        let(:edited_buffer) do
          "apiVersion: v1\nkind: Secret\nmetadata: { name: db, namespace: app }\n" \
            "type: Opaque\nstringData: { password: rotated, username: <redacted> }\n"
        end

        it "confirms the context and applies the written file" do
          expect(kubectl).to receive(:ensure_available!)
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
            expect(kubectl).to receive(:apply)
            expect(command.call.deployed).to be(true)
          end
        end
      end

      context "with deploy: false (default)" do
        let(:edited_buffer) do
          "apiVersion: v1\nkind: Secret\nmetadata: { name: db, namespace: app }\n" \
            "type: Opaque\nstringData: { password: rotated, username: <redacted> }\n"
        end

        it "never applies or confirms" do
          expect(kubectl).not_to receive(:apply)
          expect(context_guard).not_to receive(:confirm_deploy)
          command.call
        end
      end
    end
  end
end
