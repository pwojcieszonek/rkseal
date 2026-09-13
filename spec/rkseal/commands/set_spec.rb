# frozen_string_literal: true

require "thor"

RSpec.describe RKSeal::Commands::Set do
  include AdapterDoubles

  subject(:command) do
    described_class.new(
      namespace: "app", name: "db", key: key, value_source: value_source, base64: base64,
      deploy: deploy, assume_yes: assume_yes,
      kubectl: kubectl, kubeseal: kubeseal,
      context_guard: context_guard, prompt: prompt, output_dir: output_dir
    )
  end

  let(:key)          { "password" }
  let(:value_source) { -> { "s3cret" } }
  let(:base64)       { false }
  let(:deploy)       { false }
  let(:assume_yes)   { false }
  let(:kubectl)      { fake_kubectl }
  let(:kubeseal)     { fake_kubeseal }
  let(:context_guard) { fake_context_guard }
  let(:prompt)        { instance_double(Thor::Shell::Basic, say: nil, yes?: true) }
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
          type: kubernetes.io/basic-auth
    YAML
  end

  def written_path = File.join(output_dir, "db.yaml")
  def write_local! = File.write(written_path, local_sealed)

  after { FileUtils.remove_entry(output_dir) if File.directory?(output_dir) }

  # Stand in for `kubeseal -o yaml --merge-into`: rewrite the file with the
  # piped item(s) sealed in, keeping every other entry as it was.
  def stub_merge_into
    allow(kubeseal).to receive(:merge_into) do |manifest, file:, **|
      doc = YAML.safe_load_file(file)
      YAML.safe_load(manifest)["data"].each { |k, v| doc["spec"]["encryptedData"][k] = "AgA#{v}" }
      File.write(file, YAML.dump(doc))
      nil
    end
  end

  describe "#call" do
    context "with a local <name>.yaml (the working copy)" do
      before do
        write_local!
        stub_merge_into
      end

      it "never reads the cluster (neither the Secret nor the SealedSecret)" do
        expect(kubectl).not_to receive(:get_secret)
        expect(kubectl).not_to receive(:get_sealedsecret)
        command.call
      end

      context "when the value source records when it is read" do
        let(:order) { [] }
        let(:value_source) do
          lambda do
            order << :value
            "s3cret"
          end
        end

        it "probes the cert before reading the value, so a prompt never precedes a failure" do
          allow(kubeseal).to receive(:ensure_cert!) { order << :cert }
          command.call
          expect(order).to eq(%i[cert value])
        end
      end

      it "merges exactly one base64-encoded item under the preserved scope" do
        expect(kubeseal).to receive(:merge_into) do |manifest, file:, scope:|
          doc = YAML.safe_load(manifest)
          expect(doc["data"]).to eq("password" => Base64.strict_encode64("s3cret"))
          expect(doc["metadata"]).to eq("name" => "db", "namespace" => "app")
          expect(file).to eq(written_path)
          expect(scope).to eq(:strict)
        end
        command.call
      end

      it "leaves the merged item in the file and reports the written path" do
        result = command.call
        expect(YAML.safe_load_file(written_path).dig("spec", "encryptedData"))
          .to eq("password" => "AgA#{Base64.strict_encode64("s3cret")}",
                 "username" => "AgAusername")
        expect(result).to have_attributes(output_path: File.expand_path(written_path),
                                          deployed: false)
      end

      it "does not touch the file before the merge when the scope is strict" do
        expect(kubeseal).to receive(:merge_into) do |_manifest, file:, **|
          expect(File.read(file)).to eq(local_sealed)
        end
        command.call
      end

      context "when adding a brand-new key" do
        let(:key) { "apikey" }

        it "seals it alongside the untouched existing entries" do
          command.call
          expect(YAML.safe_load_file(written_path).dig("spec", "encryptedData").keys)
            .to contain_exactly("password", "username", "apikey")
        end
      end

      context "when the local file belongs to another secret" do
        let(:local_sealed) do
          "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\n" \
            "metadata: { name: db, namespace: staging }\n" \
            "spec:\n  encryptedData: { password: AgAx }\n  template: { type: Opaque }\n"
        end

        it "refuses rather than sealing under the file's identity" do
          expect(kubeseal).not_to receive(:merge_into)
          expect { command.call }
            .to raise_error(RKSeal::InvalidInputError, %r{belongs to staging/db, not app/db})
          expect(File.read(written_path)).to eq(local_sealed)
        end
      end

      context "with a non-strict scope annotation and no template annotations" do
        let(:local_sealed) do
          <<~YAML
            apiVersion: bitnami.com/v1alpha1
            kind: SealedSecret
            metadata:
              name: db
              namespace: app
              annotations:
                sealedsecrets.bitnami.com/cluster-wide: "true"
            spec:
              encryptedData: { password: AgApassword }
              template: { type: Opaque }
          YAML
        end

        it "seals under the preserved scope with an annotations map kubeseal can write into" do
          expect(kubeseal).to receive(:merge_into) do |_manifest, file:, scope:|
            expect(scope).to eq(:cluster_wide)
            template = YAML.safe_load_file(file).dig("spec", "template")
            expect(template).to eq("type" => "Opaque", "metadata" => { "annotations" => {} })
          end
          command.call
        end
      end

      context "with base64: true" do
        let(:base64)       { true }
        let(:value_source) { -> { "#{Base64.strict_encode64("s3cret")}\n" } }

        it "stores the value canonically without re-encoding it" do
          expect(kubeseal).to receive(:merge_into) do |manifest, **|
            expect(YAML.safe_load(manifest)["data"])
              .to eq("password" => Base64.strict_encode64("s3cret"))
          end
          command.call
        end

        context "when the value is line-wrapped (as `base64`/`openssl base64` emit)" do
          let(:value_source) { -> { Base64.encode64("x" * 100) } }

          it "accepts it, ignoring the whitespace" do
            expect(kubeseal).to receive(:merge_into) do |manifest, **|
              expect(YAML.safe_load(manifest)["data"])
                .to eq("password" => Base64.strict_encode64("x" * 100))
            end
            command.call
          end
        end

        context "when the value is not valid base64" do
          let(:value_source) { -> { "not*base64" } }

          it "fails fast without merging" do
            expect(kubeseal).not_to receive(:merge_into)
            expect { command.call }
              .to raise_error(RKSeal::InvalidInputError, /not valid base64/)
          end
        end

        context "when the value is only whitespace" do
          let(:value_source) { -> { "\n\n" } }

          it "is rejected as empty rather than sealed as an empty value" do
            expect(kubeseal).not_to receive(:merge_into)
            expect { command.call }.to raise_error(RKSeal::InvalidInputError, /empty/)
          end
        end
      end

      context "when the value is empty" do
        let(:value_source) { -> { "" } }

        it "fails fast and leaves the working copy untouched" do
          expect(kubeseal).not_to receive(:merge_into)
          expect { command.call }.to raise_error(RKSeal::InvalidInputError, /empty/)
          expect(File.read(written_path)).to eq(local_sealed)
        end
      end

      context "when the value source itself raises ArgumentError" do
        let(:value_source) { -> { raise ArgumentError, "invalid byte sequence" } }

        it "propagates it unchanged instead of blaming base64" do
          expect { command.call }.to raise_error(ArgumentError, "invalid byte sequence")
        end
      end

      it "keeps the working copy when kubeseal fails" do
        allow(kubeseal).to receive(:merge_into).and_raise(RKSeal::CommandError, "boom")
        expect { command.call }.to raise_error(RKSeal::CommandError)
        expect(File.read(written_path)).to eq(local_sealed)
      end
    end

    context "with no local file" do
      let(:cluster_sealed) do
        JSON.generate(
          "apiVersion" => "bitnami.com/v1alpha1", "kind" => "SealedSecret",
          "metadata" => {
            "name" => "db", "namespace" => "app", "uid" => "abc", "resourceVersion" => "42",
            "managedFields" => [{ "manager" => "kubectl" }],
            "annotations" => { "kubectl.kubernetes.io/last-applied-configuration" => "{}" }
          },
          "spec" => { "encryptedData" => { "username" => "AgAusername" },
                      "template" => { "type" => "Opaque" } },
          "status" => { "conditions" => [] }
        )
      end

      before { allow(kubectl).to receive(:get_sealedsecret).and_return(cluster_sealed) }

      it "materialises the cluster SealedSecret locally (runtime metadata stripped) and merges" do
        stub_merge_into
        expect(kubectl).to receive(:ensure_available!)
        expect(kubectl).to receive(:get_sealedsecret).with(name: "db", namespace: "app")
        command.call
        doc = YAML.safe_load_file(written_path)
        expect(doc["metadata"]).to eq("name" => "db", "namespace" => "app")
        expect(doc).not_to have_key("status")
        expect(doc.dig("spec", "encryptedData").keys).to contain_exactly("username", "password")
      end

      it "removes the materialised file again when the merge fails" do
        allow(kubeseal).to receive(:merge_into).and_raise(RKSeal::CommandError, "boom")
        expect { command.call }.to raise_error(RKSeal::CommandError)
        expect(File).not_to exist(written_path)
      end

      context "when the operator interrupts at the value prompt" do
        let(:value_source) { -> { raise Interrupt } }

        it "removes the materialised file too" do
          expect { command.call }.to raise_error(Interrupt)
          expect(File).not_to exist(written_path)
        end
      end

      it "fails fast pointing at create when the SealedSecret is absent from the cluster too" do
        allow(kubectl).to receive(:get_sealedsecret).and_raise(RKSeal::NotFoundError, "absent")
        expect(kubeseal).not_to receive(:merge_into)
        expect { command.call }.to raise_error(RKSeal::NotFoundError, /rkseal create app db/)
        expect(File).not_to exist(written_path)
      end
    end

    context "with deploy: true" do
      let(:deploy) { true }

      before do
        write_local!
        stub_merge_into
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
      before do
        write_local!
        stub_merge_into
      end

      it "never applies or confirms" do
        expect(kubectl).not_to receive(:apply)
        expect(context_guard).not_to receive(:confirm_deploy)
        command.call
      end
    end
  end
end
