# frozen_string_literal: true

RSpec.describe RKSeal::Commands::Validate do
  include AdapterDoubles

  let(:kubeseal)   { fake_kubeseal }
  let(:output_dir) { Dir.mktmpdir }
  let(:sealed_yaml) { "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\n" }

  after { FileUtils.remove_entry(output_dir) if File.directory?(output_dir) }

  describe "#call" do
    context "with NAMESPACE NAME (local <name>.yaml)" do
      subject(:command) do
        described_class.new(namespace: "app", name: "db", kubeseal: kubeseal,
                            output_dir: output_dir)
      end

      let(:path) { File.join(output_dir, "db.yaml") }

      before { File.write(path, sealed_yaml) }

      it "passes the file contents to kubeseal.validate and returns the path on success" do
        expect(kubeseal).to receive(:validate).with(sealed_yaml).and_return(true)
        expect(command.call).to eq(File.expand_path(path))
      end

      it "raises InvalidInputError when the <name>.yaml is missing" do
        FileUtils.rm_f(path)
        expect(kubeseal).not_to receive(:validate)
        expect { command.call }.to raise_error(RKSeal::InvalidInputError, /cannot read/)
      end

      it "propagates ValidationError (reason) when the controller rejects" do
        allow(kubeseal).to receive(:validate)
          .and_raise(RKSeal::ValidationError, "wrong namespace for this key")
        expect { command.call }
          .to raise_error(RKSeal::ValidationError, /wrong namespace/)
      end

      it "propagates CommandError when the validate operation itself fails" do
        allow(kubeseal).to receive(:validate)
          .and_raise(RKSeal::CommandError.new("controller unreachable"))
        expect { command.call }.to raise_error(RKSeal::CommandError, /unreachable/)
      end
    end

    context "with --file (arbitrary path)" do
      let(:file) { File.join(output_dir, "anything.yaml") }

      subject(:command) { described_class.new(file: file, kubeseal: kubeseal) }

      before { File.write(file, sealed_yaml) }

      it "validates the given file regardless of name and returns its path" do
        expect(kubeseal).to receive(:validate).with(sealed_yaml).and_return(true)
        expect(command.call).to eq(File.expand_path(file))
      end

      it "raises InvalidInputError when the file does not exist" do
        cmd = described_class.new(file: "/no/such/sealed.yaml", kubeseal: kubeseal)
        expect { cmd.call }.to raise_error(RKSeal::InvalidInputError, /cannot read/)
      end
    end
  end
end
