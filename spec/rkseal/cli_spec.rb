# frozen_string_literal: true

RSpec.describe RKSeal::CLI do
  describe ".exit_on_failure?" do
    it "is true so usage/argument errors exit non-zero" do
      expect(described_class.exit_on_failure?).to be(true)
    end
  end

  describe "command surface" do
    it "exposes create/edit/reencrypt/validate/view/list (and version) commands" do
      expect(described_class.all_commands.keys)
        .to include("create", "edit", "reencrypt", "validate", "view", "list", "version")
    end

    it "documents NAMESPACE NAME usage for create" do
      expect(described_class.all_commands.fetch("create").usage).to include("NAMESPACE", "NAME")
    end

    it "documents NAMESPACE NAME usage for edit" do
      expect(described_class.all_commands.fetch("edit").usage).to include("NAMESPACE", "NAME")
    end
  end

  describe ".dispatch" do
    let(:result) do
      RKSeal::Commands::Result.new(secret_name: "db", namespace: "app",
                                   output_path: "/cwd/db.yaml", deployed: false)
    end
    let(:command) { instance_double(RKSeal::Commands::Create, call: result) }

    # Run dispatch with stdout/stderr captured so Thor's `say`/`warn` do not
    # pollute the test output, and SystemExit is swallowed into a status.
    def run_dispatch(argv)
      status = nil
      out = StringIO.new
      err = StringIO.new
      $stdout = out
      $stderr = err
      begin
        described_class.dispatch(argv)
      rescue SystemExit => e
        status = e.status
      end
      [out.string, err.string, status]
    ensure
      $stdout = STDOUT
      $stderr = STDERR
    end

    describe "create mapping" do
      it "maps `create app db` onto Commands::Create with parsed args and prints the path" do
        allow(RKSeal::Commands::Create).to receive(:new).and_return(command)
        out, = run_dispatch(%w[create app db])
        expect(RKSeal::Commands::Create).to have_received(:new)
          .with(hash_including(namespace: "app", name: "db", scope: :strict, no_edit: false))
        expect(out).to include("/cwd/db.yaml")
      end

      it "translates the dashed --scope enum into the matching symbol" do
        allow(RKSeal::Commands::Create).to receive(:new).and_return(command)
        run_dispatch(%w[create app db --scope namespace-wide])
        expect(RKSeal::Commands::Create).to have_received(:new)
          .with(hash_including(scope: :namespace_wide))
      end

      it "parses repeatable --from-file key=path tokens into a Hash" do
        allow(RKSeal::Commands::Create).to receive(:new).and_return(command)
        run_dispatch(%w[create app db --from-file cert=/p/cert.pem key=/p/tls.key])
        expect(RKSeal::Commands::Create).to have_received(:new)
          .with(hash_including(from_file: { "cert" => "/p/cert.pem", "key" => "/p/tls.key" }))
      end

      it "keeps paths that contain '=' intact (splits on the first '=' only)" do
        allow(RKSeal::Commands::Create).to receive(:new).and_return(command)
        run_dispatch(["create", "app", "db", "--from-file", "k=/p/a=b.pem"])
        expect(RKSeal::Commands::Create).to have_received(:new)
          .with(hash_including(from_file: { "k" => "/p/a=b.pem" }))
      end

      it "forwards --no-edit, --type, and controller/cert flags (dashed = string keys)" do
        allow(RKSeal::Commands::Create).to receive(:new).and_return(command)
        allow(RKSeal::Kubeseal).to receive(:new).and_call_original
        run_dispatch(%w[create app db --no-edit --type kubernetes.io/tls
                        --controller-name sealed --controller-namespace kube-system --cert /c.pem])
        expect(RKSeal::Commands::Create).to have_received(:new)
          .with(hash_including(no_edit: true, type: "kubernetes.io/tls"))
        expect(RKSeal::Kubeseal).to have_received(:new)
          .with(hash_including(controller_name: "sealed", controller_namespace: "kube-system",
                               cert: "/c.pem"))
      end

      it "raises InvalidInputError (-> exit 1) on a malformed --from-file token" do
        _out, err, status = run_dispatch(%w[create app db --from-file no-equals-sign])
        expect(status).to eq(1)
        expect(err).to match(/--from-file expects key=path/)
      end
    end

    describe "edit mapping" do
      let(:edit_command) { instance_double(RKSeal::Commands::Edit, call: result) }

      it "maps `edit app db --deploy` onto Commands::Edit with deploy: true" do
        allow(RKSeal::Commands::Edit).to receive(:new).and_return(edit_command)
        run_dispatch(%w[edit app db --deploy])
        expect(RKSeal::Commands::Edit).to have_received(:new)
          .with(hash_including(namespace: "app", name: "db", deploy: true))
      end

      it "defaults deploy and assume_yes to false, and scope to nil (preserve existing)" do
        allow(RKSeal::Commands::Edit).to receive(:new).and_return(edit_command)
        run_dispatch(%w[edit app db])
        expect(RKSeal::Commands::Edit).to have_received(:new)
          .with(hash_including(deploy: false, assume_yes: false, scope: nil))
      end

      it "passes an explicit --scope through as the override symbol" do
        allow(RKSeal::Commands::Edit).to receive(:new).and_return(edit_command)
        run_dispatch(%w[edit app db --scope cluster-wide])
        expect(RKSeal::Commands::Edit).to have_received(:new)
          .with(hash_including(scope: :cluster_wide))
      end

      it "maps --yes onto assume_yes: true" do
        allow(RKSeal::Commands::Edit).to receive(:new).and_return(edit_command)
        run_dispatch(%w[edit app db --deploy --yes])
        expect(RKSeal::Commands::Edit).to have_received(:new)
          .with(hash_including(deploy: true, assume_yes: true))
      end

      it "prints a 'no changes' line when the command reports a nil output_path" do
        noop = RKSeal::Commands::Result.new(secret_name: "db", namespace: "app",
                                            output_path: nil, deployed: false)
        allow(RKSeal::Commands::Edit).to receive(:new)
          .and_return(instance_double(RKSeal::Commands::Edit, call: noop))
        out, = run_dispatch(%w[edit app db])
        expect(out).to match(/No changes/i)
      end

      it "announces a deploy when the command reports deployed: true" do
        deployed = RKSeal::Commands::Result.new(secret_name: "db", namespace: "app",
                                                output_path: "/cwd/db.yaml", deployed: true)
        allow(RKSeal::Commands::Edit).to receive(:new)
          .and_return(instance_double(RKSeal::Commands::Edit, call: deployed))
        out, = run_dispatch(%w[edit app db --deploy])
        expect(out).to match(/Deployed/i)
      end

      context "with --local" do
        let(:local_command) { instance_double(RKSeal::Commands::EditLocal, call: result) }

        it "routes to Commands::EditLocal instead of Commands::Edit" do
          allow(RKSeal::Commands::EditLocal).to receive(:new).and_return(local_command)
          allow(RKSeal::Commands::Edit).to receive(:new)
          run_dispatch(%w[edit app db --local --deploy --yes])
          expect(RKSeal::Commands::EditLocal).to have_received(:new)
            .with(hash_including(namespace: "app", name: "db", deploy: true, assume_yes: true))
          expect(RKSeal::Commands::Edit).not_to have_received(:new)
        end

        it "rejects --scope combined with an offline edit (exit 1)" do
          _out, err, status = run_dispatch(%w[edit app db --local --scope cluster-wide])
          expect(status).to eq(1)
          expect(err).to match(/scope cannot be changed when editing a local-only/)
        end
      end

      context "local working-copy precedence" do
        let(:local_command) { instance_double(RKSeal::Commands::EditLocal, call: result) }
        let(:edit_command)  { instance_double(RKSeal::Commands::Edit, call: result) }
        # A SealedSecret whose payload matches `local_yaml` below.
        let(:cluster_sealed) do
          '{"apiVersion":"bitnami.com/v1alpha1","kind":"SealedSecret",' \
            '"metadata":{"name":"db","namespace":"app"},' \
            '"spec":{"encryptedData":{"password":"AgAx"},"template":{"type":"Opaque"}}}'
        end
        let(:local_yaml) do
          "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\n" \
            "metadata: { name: db, namespace: app }\n" \
            "spec:\n  encryptedData: { password: AgAx }\n  template: { type: Opaque }\n"
        end
        let(:kubectl) { instance_double(RKSeal::Kubectl) }

        around do |example|
          Dir.mktmpdir { |dir| Dir.chdir(dir) { example.run } }
        end

        before { allow(RKSeal::Kubectl).to receive(:new).and_return(kubectl) }

        it "seeds from the cluster when the local file matches what is deployed" do
          File.write("db.yaml", local_yaml)
          allow(kubectl).to receive(:get_sealedsecret).and_return(cluster_sealed)
          allow(RKSeal::Commands::Edit).to receive(:new).and_return(edit_command)
          allow(RKSeal::Commands::EditLocal).to receive(:new)

          run_dispatch(%w[edit app db])

          expect(RKSeal::Commands::Edit).to have_received(:new)
          expect(RKSeal::Commands::EditLocal).not_to have_received(:new)
        end

        it "edits the local file offline (with a warning) when it diverges" do
          File.write("db.yaml", local_yaml)
          diverged = cluster_sealed.sub("AgAx", "AgAdifferent")
          allow(kubectl).to receive(:get_sealedsecret).and_return(diverged)
          allow(RKSeal::Commands::EditLocal).to receive(:new).and_return(local_command)
          allow(RKSeal::Commands::Edit).to receive(:new)

          out, = run_dispatch(%w[edit app db])

          expect(RKSeal::Commands::EditLocal).to have_received(:new)
            .with(hash_including(namespace: "app", name: "db"))
          expect(RKSeal::Commands::Edit).not_to have_received(:new)
          expect(out).to match(/changes not deployed.*offline/i)
        end

        it "edits the local file offline when the SealedSecret is not on the cluster" do
          File.write("db.yaml", local_yaml)
          allow(kubectl).to receive(:get_sealedsecret).and_raise(RKSeal::NotFoundError, "absent")
          allow(RKSeal::Commands::EditLocal).to receive(:new).and_return(local_command)
          allow(RKSeal::Commands::Edit).to receive(:new)

          out, = run_dispatch(%w[edit app db])

          expect(RKSeal::Commands::EditLocal).to have_received(:new)
          expect(out).to match(/not deployed to the cluster.*offline/i)
        end

        it "re-raises (exit 1, points at create) when neither cluster nor local exist" do
          absent = instance_double(RKSeal::Commands::Edit)
          allow(absent).to receive(:call).and_raise(RKSeal::NotFoundError, "use rkseal create")
          allow(RKSeal::Commands::Edit).to receive(:new).and_return(absent)
          allow(RKSeal::Commands::EditLocal).to receive(:new)

          _out, err, status = run_dispatch(%w[edit app db])

          expect(status).to eq(1)
          expect(err).to match(/rkseal create/)
          expect(RKSeal::Commands::EditLocal).not_to have_received(:new)
        end
      end
    end

    describe "reencrypt mapping" do
      let(:reencrypt_command) { instance_double(RKSeal::Commands::Reencrypt, call: result) }

      it "maps `reencrypt app db` onto Commands::Reencrypt and prints the path" do
        allow(RKSeal::Commands::Reencrypt).to receive(:new).and_return(reencrypt_command)
        out, = run_dispatch(%w[reencrypt app db])
        expect(RKSeal::Commands::Reencrypt).to have_received(:new)
          .with(hash_including(namespace: "app", name: "db", deploy: false, assume_yes: false))
        expect(out).to include("/cwd/db.yaml")
      end

      it "maps --deploy and --yes through" do
        allow(RKSeal::Commands::Reencrypt).to receive(:new).and_return(reencrypt_command)
        run_dispatch(%w[reencrypt app db --deploy --yes])
        expect(RKSeal::Commands::Reencrypt).to have_received(:new)
          .with(hash_including(deploy: true, assume_yes: true))
      end

      it "validates the identifiers (rejects a traversal name before building)" do
        expect(RKSeal::Commands::Reencrypt).not_to receive(:new)
        _out, _err, status = run_dispatch(["reencrypt", "app", "../bad"])
        expect(status).to eq(1)
      end
    end

    describe "validate mapping" do
      let(:validate_command) { instance_double(RKSeal::Commands::Validate, call: "/cwd/db.yaml") }

      it "maps `validate app db` onto Commands::Validate and prints a valid line" do
        allow(RKSeal::Commands::Validate).to receive(:new).and_return(validate_command)
        out, = run_dispatch(%w[validate app db])
        expect(RKSeal::Commands::Validate).to have_received(:new)
          .with(hash_including(namespace: "app", name: "db", file: nil))
        expect(out).to match(/valid/i)
      end

      it "accepts --file without NAMESPACE NAME" do
        allow(RKSeal::Commands::Validate).to receive(:new).and_return(validate_command)
        run_dispatch(%w[validate --file out/db.yaml])
        expect(RKSeal::Commands::Validate).to have_received(:new)
          .with(hash_including(file: "out/db.yaml"))
      end

      it "errors (exit 1) when neither NAME nor --file is given" do
        expect(RKSeal::Commands::Validate).not_to receive(:new)
        _out, err, status = run_dispatch(%w[validate])
        expect(status).to eq(1)
        expect(err).to match(/NAMESPACE NAME or --file/)
      end

      it "exits non-zero and prints the reason on a ValidationError (no backtrace)" do
        failing = instance_double(RKSeal::Commands::Validate)
        allow(failing).to receive(:call)
          .and_raise(RKSeal::ValidationError, "wrong namespace for this sealing key")
        allow(RKSeal::Commands::Validate).to receive(:new).and_return(failing)
        _out, err, status = run_dispatch(%w[validate app db])
        expect(status).to eq(1)
        expect(err).to include("wrong namespace for this sealing key")
        expect(err).not_to include("ValidationError")
      end
    end

    describe "view mapping" do
      let(:view_command) { instance_double(RKSeal::Commands::View, call: "kind: Secret\n") }

      it "maps `view app db` onto Commands::View and prints the manifest" do
        allow(RKSeal::Commands::View).to receive(:new).and_return(view_command)
        out, = run_dispatch(%w[view app db])
        expect(RKSeal::Commands::View).to have_received(:new)
          .with(hash_including(namespace: "app", name: "db", reveal: false))
        expect(out).to include("kind: Secret")
      end

      it "maps --reveal onto reveal: true" do
        allow(RKSeal::Commands::View).to receive(:new).and_return(view_command)
        run_dispatch(%w[view app db --reveal])
        expect(RKSeal::Commands::View).to have_received(:new)
          .with(hash_including(reveal: true))
      end

      it "validates the identifiers (rejects a leading-dash name before building)" do
        expect(RKSeal::Commands::View).not_to receive(:new)
        _out, _err, status = run_dispatch(["view", "app", "-rf"])
        expect(status).to eq(1)
      end
    end

    describe "list mapping" do
      let(:list_command) { instance_double(RKSeal::Commands::List, call: "NAMESPACE   NAME\n") }

      it "maps `list` (no namespace) onto Commands::List with namespace: nil" do
        allow(RKSeal::Commands::List).to receive(:new).and_return(list_command)
        out, = run_dispatch(%w[list])
        expect(RKSeal::Commands::List).to have_received(:new)
          .with(hash_including(namespace: nil))
        expect(out).to include("NAMESPACE")
      end

      it "maps `list app` onto Commands::List with the given namespace" do
        allow(RKSeal::Commands::List).to receive(:new).and_return(list_command)
        run_dispatch(%w[list app])
        expect(RKSeal::Commands::List).to have_received(:new)
          .with(hash_including(namespace: "app"))
      end

      it "rejects an invalid namespace (DNS-1123) before building the command" do
        expect(RKSeal::Commands::List).not_to receive(:new)
        _out, _err, status = run_dispatch(["list", "../evil"])
        expect(status).to eq(1)
      end
    end

    describe "error handling" do
      it "prints a single clean line on stderr and exits non-zero on a raised RKSeal::Error" do
        failing = instance_double(RKSeal::Commands::Edit)
        allow(failing).to receive(:call)
          .and_raise(RKSeal::NotFoundError, "Secret app/db not found; run `rkseal create`")
        allow(RKSeal::Commands::Edit).to receive(:new).and_return(failing)
        _out, err, status = run_dispatch(%w[edit app db])
        expect(status).to eq(1)
        expect(err.lines.size).to eq(1)
        expect(err).to include("rkseal create")
        expect(err).not_to include("NotFoundError") # no class name / backtrace
      end

      it "lets unexpected (non-RKSeal::Error) exceptions propagate" do
        boom = instance_double(RKSeal::Commands::Create)
        allow(boom).to receive(:call).and_raise(RuntimeError, "genuine bug")
        allow(RKSeal::Commands::Create).to receive(:new).and_return(boom)
        expect { run_dispatch(%w[create app db]) }.to raise_error(RuntimeError, "genuine bug")
      end
    end

    describe "version" do
      it "prints the gem version" do
        out, = run_dispatch(%w[version])
        expect(out).to include(RKSeal::VERSION)
      end
    end

    describe "identifier validation (security boundary)" do
      # A malformed name/namespace must be rejected at the CLI BEFORE any command
      # is constructed -- no editor, no cluster call, no kubectl/kubeseal argv.
      %w[
        ../../etc/passwd
        ..
        a/b
        -ojson
        UPPER
        with_underscore
      ].each do |bad|
        it "rejects an invalid name #{bad.inspect} (exit 1) without building a command" do
          expect(RKSeal::Commands::Create).not_to receive(:new)
          _out, err, status = run_dispatch(["create", "app", bad])
          expect(status).to eq(1)
          expect(err).to match(/not a valid Kubernetes name|too long|must not be empty/)
        end

        it "rejects an invalid namespace #{bad.inspect} (exit 1) on edit too" do
          expect(RKSeal::Commands::Edit).not_to receive(:new)
          _out, _err, status = run_dispatch(["edit", bad, "db"])
          expect(status).to eq(1)
        end
      end

      it "accepts a valid DNS-1123 name and namespace" do
        allow(RKSeal::Commands::Create).to receive(:new)
          .and_return(instance_double(RKSeal::Commands::Create, call: result))
        _out, _err, status = run_dispatch(%w[create my-app my-secret.v2])
        expect(status).to be_nil # no SystemExit raised
        expect(RKSeal::Commands::Create).to have_received(:new)
      end
    end

    describe "controller-flag validation (flag-injection safety)" do
      # --controller-name/--controller-namespace flow straight into kubeseal's
      # --controller-name/--controller-namespace flags, so a traversal or
      # leading-dash value must be rejected at the boundary, before any Kubeseal
      # adapter is built.
      it "rejects a traversal --controller-namespace before building the adapter" do
        expect(RKSeal::Kubeseal).not_to receive(:new)
        expect(RKSeal::Commands::Create).not_to receive(:new)
        _out, err, status = run_dispatch(["create", "app", "db",
                                          "--controller-namespace", "../../tmp/evil"])
        expect(status).to eq(1)
        expect(err).to match(/--controller-namespace .* is not a valid Kubernetes name/)
      end

      it "rejects a traversal --controller-name" do
        expect(RKSeal::Kubeseal).not_to receive(:new)
        _out, err, status = run_dispatch(["edit", "app", "db",
                                          "--controller-name", "../escape"])
        expect(status).to eq(1)
        expect(err).to match(/--controller-name/)
      end

      it "rejects a leading-dash --controller-name (argument injection) on reencrypt" do
        expect(RKSeal::Kubeseal).not_to receive(:new)
        _out, _err, status = run_dispatch(["reencrypt", "app", "db",
                                           "--controller-name", "-rf"])
        expect(status).to eq(1)
      end

      it "passes valid controller flags through to Kubeseal.new" do
        allow(RKSeal::Commands::Create).to receive(:new)
          .and_return(instance_double(RKSeal::Commands::Create, call: result))
        allow(RKSeal::Kubeseal).to receive(:new).and_call_original
        run_dispatch(%w[create app db --controller-name sealed-secrets
                        --controller-namespace kube-system])
        expect(RKSeal::Kubeseal).to have_received(:new)
          .with(hash_including(controller_name: "sealed-secrets",
                               controller_namespace: "kube-system"))
      end
    end
  end
end
