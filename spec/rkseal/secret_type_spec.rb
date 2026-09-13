# frozen_string_literal: true

require "base64"
require "json"

RSpec.describe RKSeal::SecretType do
  def b64(plain) = Base64.strict_encode64(plain)

  def secret(type:, data: {}, name: "db", namespace: "app", metadata: {})
    RKSeal::Secret.new(name: name, namespace: namespace, type: type,
                       data: data.transform_values { |v| b64(v) }, metadata: metadata)
  end

  describe ".for" do
    it "resolves every built-in type by name" do
      expect(described_class.known.keys).to contain_exactly(
        "Opaque",
        "kubernetes.io/service-account-token",
        "kubernetes.io/dockercfg",
        "kubernetes.io/dockerconfigjson",
        "kubernetes.io/basic-auth",
        "kubernetes.io/ssh-auth",
        "kubernetes.io/tls",
        "bootstrap.kubernetes.io/token"
      )
      described_class.known.each_key do |name|
        expect(described_class.for(name)).to be_known
      end
    end

    it "accepts a custom type string with no key rules" do
      custom = described_class.for("example.com/my-type")
      expect(custom).not_to be_known
      expect(custom.required_keys).to be_empty
      expect { custom.validate!(secret(type: "example.com/my-type", data: { "k" => "v" })) }
        .not_to raise_error
    end

    it "rejects an unknown type under the reserved kubernetes.io/ prefix" do
      expect { described_class.for("kubernetes.io/tsl") }
        .to raise_error(RKSeal::InvalidInputError, %r{unknown Secret type "kubernetes.io/tsl"})
    end

    it "rejects an unknown type under bootstrap.kubernetes.io/" do
      expect { described_class.for("bootstrap.kubernetes.io/tokenz") }
        .to raise_error(RKSeal::InvalidInputError, /reserved Kubernetes prefix/)
    end
  end

  describe "#seed_data / #seed_annotations" do
    it "seeds nothing for Opaque" do
      expect(described_class.for("Opaque").seed_data).to eq({})
      expect(described_class.for("Opaque").seed_annotations).to eq({})
    end

    it "seeds the required keys with empty values" do
      expect(described_class.for("kubernetes.io/tls").seed_data)
        .to eq("tls.crt" => "", "tls.key" => "")
    end

    it "seeds both any-of keys for basic-auth" do
      expect(described_class.for("kubernetes.io/basic-auth").seed_data)
        .to eq("username" => "", "password" => "")
    end

    it "seeds the required annotation (and no data) for service-account-token" do
      type = described_class.for("kubernetes.io/service-account-token")
      expect(type.seed_data).to eq({})
      expect(type.seed_annotations).to eq("kubernetes.io/service-account.name" => "")
    end
  end

  describe "#validate!" do
    context "Opaque" do
      it "rejects an empty data map" do
        expect { described_class.for("Opaque").validate!(secret(type: "Opaque")) }
          .to raise_error(RKSeal::InvalidInputError, /no data items/)
      end

      it "accepts any keys" do
        opaque = described_class.for("Opaque")
        expect { opaque.validate!(secret(type: "Opaque", data: { "x" => "y" })) }.not_to raise_error
      end
    end

    context "kubernetes.io/tls" do
      let(:type) { described_class.for("kubernetes.io/tls") }

      it "requires both tls.crt and tls.key" do
        expect { type.validate!(secret(type: type.name, data: { "tls.crt" => "c" })) }
          .to raise_error(RKSeal::InvalidInputError, /requires tls\.key/)
      end

      it "rejects a required key left empty (the untouched seed placeholder)" do
        data = { "tls.crt" => "c", "tls.key" => "" }
        expect { type.validate!(secret(type: type.name, data: data)) }
          .to raise_error(RKSeal::InvalidInputError, /"tls\.key" is empty/)
      end

      it "accepts a complete pair, with the optional ca.crt" do
        data = { "tls.crt" => "c", "tls.key" => "k", "ca.crt" => "ca" }
        expect { type.validate!(secret(type: type.name, data: data)) }.not_to raise_error
      end
    end

    context "kubernetes.io/ssh-auth" do
      let(:type) { described_class.for("kubernetes.io/ssh-auth") }

      it "requires ssh-privatekey" do
        expect { type.validate!(secret(type: type.name, data: { "id_rsa" => "k" })) }
          .to raise_error(RKSeal::InvalidInputError, /requires ssh-privatekey/)
      end

      it "accepts ssh-privatekey" do
        expect { type.validate!(secret(type: type.name, data: { "ssh-privatekey" => "k" })) }
          .not_to raise_error
      end
    end

    context "kubernetes.io/basic-auth" do
      let(:type) { described_class.for("kubernetes.io/basic-auth") }

      it "requires username or password to be present" do
        expect { type.validate!(secret(type: type.name, data: { "token" => "t" })) }
          .to raise_error(RKSeal::InvalidInputError, /at least one of username, password/)
      end

      it "rejects both seeded placeholders left empty" do
        data = { "username" => "", "password" => "" }
        expect { type.validate!(secret(type: type.name, data: data)) }
          .to raise_error(RKSeal::InvalidInputError, /non-empty value for at least one/)
      end

      it "accepts an empty username next to a set password (apiserver semantics)" do
        data = { "username" => "", "password" => "p" }
        expect { type.validate!(secret(type: type.name, data: data)) }.not_to raise_error
      end
    end

    context "kubernetes.io/dockerconfigjson" do
      let(:type) { described_class.for("kubernetes.io/dockerconfigjson") }
      let(:config) { { "auths" => { "reg.example" => { "auth" => "dXNlcjpwdw==" } } }.to_json }

      it "requires .dockerconfigjson" do
        expect { type.validate!(secret(type: type.name, data: { "config.json" => config })) }
          .to raise_error(RKSeal::InvalidInputError, /requires \.dockerconfigjson/)
      end

      it "rejects a value that is not JSON without echoing the value" do
        data = { ".dockerconfigjson" => "hunter2{" }
        expect { type.validate!(secret(type: type.name, data: data)) }
          .to raise_error(RKSeal::InvalidInputError) { |e|
            expect(e.message).to match(/not valid JSON/)
            expect(e.message).not_to include("hunter2")
          }
      end

      it "rejects a JSON value that is not an object" do
        expect { type.validate!(secret(type: type.name, data: { ".dockerconfigjson" => "[1]" })) }
          .to raise_error(RKSeal::InvalidInputError, /must be a JSON object/)
      end

      it "rejects an object without an auths map" do
        expect { type.validate!(secret(type: type.name, data: { ".dockerconfigjson" => "{}" })) }
          .to raise_error(RKSeal::InvalidInputError, /"auths"/)
      end

      it "accepts a ~/.docker/config.json payload" do
        expect { type.validate!(secret(type: type.name, data: { ".dockerconfigjson" => config })) }
          .not_to raise_error
      end
    end

    context "kubernetes.io/dockercfg" do
      let(:type) { described_class.for("kubernetes.io/dockercfg") }

      it "requires .dockercfg to be a JSON object" do
        expect { type.validate!(secret(type: type.name, data: { ".dockercfg" => "nope" })) }
          .to raise_error(RKSeal::InvalidInputError, /not valid JSON/)
      end

      it "accepts the legacy registry map (no auths wrapper needed)" do
        legacy = { "reg.example" => { "auth" => "dXNlcjpwdw==" } }.to_json
        expect { type.validate!(secret(type: type.name, data: { ".dockercfg" => legacy })) }
          .not_to raise_error
      end
    end

    context "kubernetes.io/service-account-token" do
      let(:type) { described_class.for("kubernetes.io/service-account-token") }
      let(:annotated) { { "annotations" => { "kubernetes.io/service-account.name" => "builder" } } }

      it "requires the service-account.name annotation" do
        expect { type.validate!(secret(type: type.name)) }
          .to raise_error(RKSeal::InvalidInputError, %r{kubernetes\.io/service-account\.name})
      end

      it "rejects the annotation left empty" do
        empty = { "annotations" => { "kubernetes.io/service-account.name" => "" } }
        expect { type.validate!(secret(type: type.name, metadata: empty)) }
          .to raise_error(RKSeal::InvalidInputError, /requires the annotation/)
      end

      it "accepts an empty data map once the annotation is set (controller fills the token)" do
        expect { type.validate!(secret(type: type.name, metadata: annotated)) }.not_to raise_error
      end
    end

    context "bootstrap.kubernetes.io/token" do
      let(:type) { described_class.for("bootstrap.kubernetes.io/token") }
      let(:valid) { { "token-id" => "abcdef", "token-secret" => "0123456789abcdef" } }

      def bootstrap(data: valid, name: "bootstrap-token-abcdef", namespace: "kube-system")
        secret(type: type.name, data: data, name: name, namespace: namespace)
      end

      it "accepts a well-formed token in kube-system with the matching name" do
        expect { type.validate!(bootstrap) }.not_to raise_error
      end

      it "requires token-id and token-secret" do
        expect { type.validate!(bootstrap(data: { "token-id" => "abcdef" })) }
          .to raise_error(RKSeal::InvalidInputError, /requires token-secret/)
      end

      it "rejects a token-id of the wrong shape" do
        expect { type.validate!(bootstrap(data: valid.merge("token-id" => "ABCDEF"))) }
          .to raise_error(RKSeal::InvalidInputError, /"token-id" must match/)
      end

      it "rejects a token-secret of the wrong length" do
        expect { type.validate!(bootstrap(data: valid.merge("token-secret" => "short"))) }
          .to raise_error(RKSeal::InvalidInputError, /"token-secret" must match/)
      end

      it "rejects a namespace other than kube-system" do
        expect { type.validate!(bootstrap(namespace: "app")) }
          .to raise_error(RKSeal::InvalidInputError, /must live in the kube-system namespace/)
      end

      it "rejects a name that does not embed the token-id" do
        expect { type.validate!(bootstrap(name: "bootstrap-token-zzzzzz")) }
          .to raise_error(RKSeal::InvalidInputError, /must be named bootstrap-token-abcdef/)
      end
    end
  end

  describe "#validate_keys! / #validate_values! (offline local edit)" do
    let(:tls) { described_class.for("kubernetes.io/tls") }

    it "checks presence over an arbitrary key set (kept ciphertext exposes only keys)" do
      expect { tls.validate_keys!(%w[tls.crt]) }
        .to raise_error(RKSeal::InvalidInputError, /requires tls\.key/)
      expect { tls.validate_keys!(%w[tls.crt tls.key]) }.not_to raise_error
    end

    it "allows an empty key set only for a data-optional type" do
      expect { tls.validate_keys!([]) }.to raise_error(RKSeal::InvalidInputError, /no data items/)
      expect { described_class.for("kubernetes.io/service-account-token").validate_keys!([]) }
        .not_to raise_error
    end

    it "checks values only for the type-mandated keys that are present" do
      expect { tls.validate_values!("tls.key" => b64("")) }
        .to raise_error(RKSeal::InvalidInputError, /"tls\.key" is empty/)
      expect { tls.validate_values!("other" => b64("")) }.not_to raise_error
    end
  end
end
