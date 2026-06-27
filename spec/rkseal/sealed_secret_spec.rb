# frozen_string_literal: true

RSpec.describe RKSeal::SealedSecret do
  let(:sealed_yaml) do
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

  describe ".parse" do
    subject(:sealed) { described_class.parse(sealed_yaml) }

    it "reads name, namespace, and the (plaintext) data keys" do
      expect(sealed).to have_attributes(
        name: "db", namespace: "app", encrypted_keys: %w[password username]
      )
    end

    it "reads the template type" do
      expect(sealed.type).to eq("Opaque")
    end

    it "defaults the type to Opaque when the template has none" do
      yaml = <<~YAML
        apiVersion: bitnami.com/v1alpha1
        kind: SealedSecret
        metadata: { name: db, namespace: app }
        spec:
          encryptedData: { password: AgAx }
      YAML
      expect(described_class.parse(yaml).type).to eq("Opaque")
    end

    it "defaults the scope to strict when no annotation is present" do
      expect(sealed.scope).to eq(:strict)
    end

    it "derives namespace-wide scope from the annotation" do
      yaml = <<~YAML
        apiVersion: bitnami.com/v1alpha1
        kind: SealedSecret
        metadata:
          name: db
          namespace: app
          annotations:
            sealedsecrets.bitnami.com/namespace-wide: "true"
        spec:
          encryptedData: { password: AgAx }
      YAML
      expect(described_class.parse(yaml).scope).to eq(:namespace_wide)
    end

    it "returns an empty key list when encryptedData is absent" do
      yaml = <<~YAML
        apiVersion: bitnami.com/v1alpha1
        kind: SealedSecret
        metadata: { name: db, namespace: app }
        spec: {}
      YAML
      expect(described_class.parse(yaml).encrypted_keys).to eq([])
    end

    it "accepts a pre-parsed Hash too" do
      expect(described_class.parse(YAML.safe_load(sealed_yaml)).name).to eq("db")
    end

    it "raises on a non-SealedSecret kind" do
      yaml = "apiVersion: v1\nkind: Secret\nmetadata: { name: db }\n"
      expect { described_class.parse(yaml) }
        .to raise_error(RKSeal::InvalidInputError, /not a SealedSecret/)
    end

    it "raises on an empty document" do
      expect { described_class.parse("   \n") }
        .to raise_error(RKSeal::InvalidInputError, /empty/)
    end

    it "raises on invalid YAML" do
      expect { described_class.parse("kind: SealedSecret\n  : :bad") }
        .to raise_error(RKSeal::InvalidInputError, /not valid YAML/)
    end

    it "raises when metadata.name is missing" do
      yaml = "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nspec: {}\n"
      expect { described_class.parse(yaml) }
        .to raise_error(RKSeal::InvalidInputError, /missing metadata.name/)
    end

    it "raises when encryptedData is not a mapping" do
      yaml = <<~YAML
        apiVersion: bitnami.com/v1alpha1
        kind: SealedSecret
        metadata: { name: db, namespace: app }
        spec:
          encryptedData: "oops"
      YAML
      expect { described_class.parse(yaml) }
        .to raise_error(RKSeal::InvalidInputError, /encryptedData must be a mapping/)
    end
  end

  describe ".diverged?" do
    let(:cluster_json) do
      '{"apiVersion":"bitnami.com/v1alpha1","kind":"SealedSecret",' \
        '"metadata":{"name":"db","namespace":"app","managedFields":[{"x":1}]},' \
        '"spec":{"encryptedData":{"password":"AgApassword","username":"AgAusername"},' \
        '"template":{"metadata":{"name":"db","namespace":"app"},"type":"Opaque"}}}'
    end

    it "is false when the local file's payload matches the cluster object's" do
      expect(described_class.diverged?(sealed_yaml, cluster_json)).to be(false)
    end

    it "ignores non-payload metadata noise like managedFields" do
      # cluster_json carries managedFields the local file lacks; still not diverged.
      expect(described_class.diverged?(sealed_yaml, cluster_json)).to be(false)
    end

    it "is true when an encryptedData value differs (a re-sealed key)" do
      changed = cluster_json.sub("AgApassword", "AgAdifferentCiphertext")
      expect(described_class.diverged?(sealed_yaml, changed)).to be(true)
    end

    it "is true when a key was added locally" do
      local = sealed_yaml.sub("    username: AgAusername\n",
                              "    username: AgAusername\n    apikey: AgAnew\n")
      expect(described_class.diverged?(local, cluster_json)).to be(true)
    end

    it "is true when the template type differs" do
      changed = cluster_json.sub('"type":"Opaque"', '"type":"kubernetes.io/basic-auth"')
      expect(described_class.diverged?(sealed_yaml, changed)).to be(true)
    end

    it "treats a malformed cluster document as diverged (never overwrites local)" do
      expect(described_class.diverged?(sealed_yaml, "not: : valid")).to be(true)
    end
  end

  describe "#to_buffer" do
    subject(:buffer) { described_class.parse(sealed_yaml).to_buffer }

    it "renders a Secret manifest with every key redacted under data (base64) by default" do
      doc = YAML.safe_load(buffer)
      expect(doc).to include(
        "apiVersion" => "v1", "kind" => "Secret", "type" => "Opaque",
        "metadata" => { "name" => "db", "namespace" => "app" },
        "data" => {
          "password" => described_class::REDACTED_PLACEHOLDER,
          "username" => described_class::REDACTED_PLACEHOLDER
        }
      )
      expect(doc).not_to have_key("stringData")
    end

    it "puts the redacted keys under stringData with string_data: true" do
      doc = YAML.safe_load(described_class.parse(sealed_yaml).to_buffer(string_data: true))
      expect(doc["stringData"]).to eq(
        "password" => described_class::REDACTED_PLACEHOLDER,
        "username" => described_class::REDACTED_PLACEHOLDER
      )
      expect(doc).not_to have_key("data")
    end

    it "includes the explanatory header by default" do
      expect(buffer).to match(/LOCAL edit of a SealedSecret/)
      expect(buffer).to match(/#{Regexp.escape(described_class::REDACTED_PLACEHOLDER)}/)
    end

    it "omits the header with commented: false" do
      plain = described_class.parse(sealed_yaml).to_buffer(commented: false)
      expect(plain).not_to match(/^#/)
    end

    it "offers an empty data block when there are no keys yet" do
      yaml = <<~YAML
        apiVersion: bitnami.com/v1alpha1
        kind: SealedSecret
        metadata: { name: db, namespace: app }
        spec: {}
      YAML
      doc = YAML.safe_load(described_class.parse(yaml).to_buffer)
      expect(doc["data"]).to eq({})
    end
  end
end
