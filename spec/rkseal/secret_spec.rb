# frozen_string_literal: true

require "base64"
require "json"

RSpec.describe RKSeal::Secret do
  def b64(plain) = Base64.strict_encode64(plain)

  describe ".validate_identifier!" do
    it "accepts valid DNS-1123 subdomains" do
      %w[db my-secret a app.team.v2 x123 0abc].each do |value|
        expect { described_class.validate_identifier!(field: "name", value: value) }
          .not_to raise_error
      end
    end

    it "returns the value for chaining" do
      expect(described_class.validate_identifier!(field: "name", value: "db")).to eq("db")
    end

    it "rejects path-traversal and argument-injection shapes" do
      bad_values = ["../etc", "..", "a/b", "/abs", "-ojson", "-rf",
                    "DB", "with_underscore", "trailing-"]
      bad_values.each do |bad|
        expect { described_class.validate_identifier!(field: "name", value: bad) }
          .to raise_error(RKSeal::InvalidInputError, /not a valid Kubernetes name/)
      end
    end

    it "rejects empty values" do
      expect { described_class.validate_identifier!(field: "namespace", value: "") }
        .to raise_error(RKSeal::InvalidInputError, /must not be empty/)
    end

    it "rejects values longer than 253 characters" do
      expect { described_class.validate_identifier!(field: "name", value: "a" * 254) }
        .to raise_error(RKSeal::InvalidInputError, /too long/)
    end

    it "names the offending field in the message" do
      expect { described_class.validate_identifier!(field: "namespace", value: "Bad") }
        .to raise_error(RKSeal::InvalidInputError, /namespace/)
    end
  end

  describe ".scope_from_sealed_json" do
    def sealed(annotations)
      { "kind" => "SealedSecret", "metadata" => { "annotations" => annotations } }
    end

    it "returns :cluster_wide for the cluster-wide annotation" do
      json = sealed("sealedsecrets.bitnami.com/cluster-wide" => "true").to_json
      expect(described_class.scope_from_sealed_json(json)).to eq(:cluster_wide)
    end

    it "returns :namespace_wide for the namespace-wide annotation" do
      json = sealed("sealedsecrets.bitnami.com/namespace-wide" => "true").to_json
      expect(described_class.scope_from_sealed_json(json)).to eq(:namespace_wide)
    end

    it "returns :strict when no scope annotation is present" do
      json = sealed("unrelated" => "x").to_json
      expect(described_class.scope_from_sealed_json(json)).to eq(:strict)
    end

    it "treats a non-\"true\" annotation value as not set (:strict)" do
      json = sealed("sealedsecrets.bitnami.com/cluster-wide" => "false").to_json
      expect(described_class.scope_from_sealed_json(json)).to eq(:strict)
    end

    it "tolerates malformed input and defaults to :strict" do
      expect(described_class.scope_from_sealed_json("{ not json")).to eq(:strict)
    end

    it "parses a YAML SealedSecret (local <name>.yaml), not only JSON" do
      yaml = <<~YAML
        kind: SealedSecret
        metadata:
          annotations:
            sealedsecrets.bitnami.com/cluster-wide: "true"
      YAML
      expect(described_class.scope_from_sealed_json(yaml)).to eq(:cluster_wide)
    end

    it "accepts a pre-parsed Hash" do
      hash = sealed("sealedsecrets.bitnami.com/namespace-wide" => "true")
      expect(described_class.scope_from_sealed_json(hash)).to eq(:namespace_wide)
    end
  end

  describe ".seed" do
    subject(:secret) { described_class.seed(name: "db", namespace: "app") }

    it "builds a minimal valid Secret skeleton for the given name/namespace/type" do
      typed = described_class.seed(name: "tls", namespace: "app", type: "kubernetes.io/tls")
      expect(typed).to have_attributes(name: "tls", namespace: "app", type: "kubernetes.io/tls")
    end

    it "defaults type to Opaque" do
      expect(secret.type).to eq("Opaque")
    end

    it "starts with no data items (empty?)" do
      expect(secret).to be_empty
    end

    it "offers an empty data (base64) block in the buffer by default" do
      buffer = YAML.safe_load(secret.to_buffer)
      expect(buffer).to include("data" => {})
      expect(buffer).not_to have_key("stringData")
    end

    it "offers an empty stringData block with string_data: true (plaintext entry)" do
      buffer = YAML.safe_load(secret.to_buffer(string_data: true))
      expect(buffer).to include("stringData" => {})
      expect(buffer).not_to have_key("data")
    end
  end

  describe ".from_kubectl_json" do
    let(:json) do
      {
        "apiVersion" => "v1", "kind" => "Secret",
        "metadata" => {
          "name" => "db", "namespace" => "app",
          "creationTimestamp" => "2024-01-01T00:00:00Z", "resourceVersion" => "42",
          "uid" => "abc", "managedFields" => [{ "manager" => "kubectl" }],
          "ownerReferences" => [{ "kind" => "Deployment" }],
          "annotations" => {
            "kubectl.kubernetes.io/last-applied-configuration" => "{stale-copy}",
            "team" => "platform"
          },
          "labels" => { "app" => "db" }
        },
        "type" => "Opaque",
        "data" => { "user" => b64("alice") }
      }.to_json
    end

    subject(:secret) { described_class.from_kubectl_json(json) }

    it "keeps .data as base64 (does NOT decode to plaintext)" do
      expect(secret.data).to eq("user" => b64("alice"))
    end

    it "renders the base64 data verbatim into the edit buffer" do
      expect(YAML.safe_load(secret.to_buffer).fetch("data")).to eq("user" => b64("alice"))
    end

    it "folds .stringData in (encoded), with stringData winning per key" do
      doc = JSON.parse(json).merge("stringData" => { "user" => "override", "token" => "t" })
      folded = described_class.from_kubectl_json(doc.to_json)
      expect(folded.data).to eq("user" => b64("override"), "token" => b64("t"))
    end

    it "strips runtime metadata (creationTimestamp, resourceVersion, uid, managedFields, ...)" do
      expect(secret.metadata.keys).not_to include(
        "creationTimestamp", "resourceVersion", "uid", "managedFields", "ownerReferences"
      )
    end

    it "removes the kubectl last-applied-configuration annotation but keeps author annotations" do
      expect(secret.metadata.fetch("annotations")).to eq("team" => "platform")
    end

    it "preserves author-owned labels" do
      expect(secret.metadata.fetch("labels")).to eq("app" => "db")
    end

    it "accepts an already-parsed Hash as well as a JSON string" do
      expect(described_class.from_kubectl_json(JSON.parse(json))).to eq(secret)
    end

    it "raises InvalidInputError when the document is not a Secret" do
      bad = { "apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => { "name" => "x" } }.to_json
      expect { described_class.from_kubectl_json(bad) }
        .to raise_error(RKSeal::InvalidInputError, /not a Kubernetes Secret/)
    end

    it "raises InvalidInputError when .data carries non-decodable base64" do
      bad = { "apiVersion" => "v1", "kind" => "Secret",
              "metadata" => { "name" => "x", "namespace" => "a" },
              "data" => { "k" => "!!!not-base64!!!" } }.to_json
      expect { described_class.from_kubectl_json(bad) }
        .to raise_error(RKSeal::InvalidInputError, /not valid base64/)
    end

    it "raises InvalidInputError on syntactically invalid JSON" do
      expect { described_class.from_kubectl_json("{ not json") }
        .to raise_error(RKSeal::InvalidInputError, /valid JSON/)
    end
  end

  describe ".from_buffer" do
    let(:buffer) do
      <<~YAML
        apiVersion: v1
        kind: Secret
        metadata:
          name: db
          namespace: app
        type: Opaque
        data:
          existing: #{b64("kept")}
        stringData:
          existing: overridden
          fresh: plaintext
      YAML
    end

    it "folds data (base64 verbatim) and stringData (plaintext), stringData winning per key" do
      secret = described_class.from_buffer(buffer)
      expect(secret.data).to eq("existing" => b64("overridden"), "fresh" => b64("plaintext"))
    end

    it "normalizes the resulting Secret to emit clean data only (no stringData) in the manifest" do
      manifest = YAML.safe_load(described_class.from_buffer(buffer).to_manifest)
      expect(manifest).to have_key("data")
      expect(manifest).not_to have_key("stringData")
    end

    it "tolerates surrounding whitespace/newlines around a base64 data value" do
      yaml = <<~YAML
        apiVersion: v1
        kind: Secret
        metadata: { name: db, namespace: app }
        data:
          blob: |
            #{b64("payload")}
      YAML
      expect(described_class.from_buffer(yaml).data.fetch("blob")).to eq(b64("payload"))
    end

    it "raises InvalidInputError on an empty buffer" do
      expect { described_class.from_buffer("   \n") }
        .to raise_error(RKSeal::InvalidInputError, /empty/)
    end

    it "raises InvalidInputError on YAML syntax errors" do
      expect { described_class.from_buffer("data: [unterminated") }
        .to raise_error(RKSeal::InvalidInputError, /not valid YAML/)
    end

    it "raises InvalidInputError on the wrong kind/apiVersion" do
      expect { described_class.from_buffer("apiVersion: v1\nkind: Pod\nmetadata: { name: x }\n") }
        .to raise_error(RKSeal::InvalidInputError, /not a Kubernetes Secret/)
    end

    it "raises InvalidInputError when name is missing" do
      yaml = "apiVersion: v1\nkind: Secret\nmetadata: { namespace: app }\nstringData: { a: b }\n"
      expect { described_class.from_buffer(yaml) }
        .to raise_error(RKSeal::InvalidInputError, /metadata.name/)
    end

    it "raises InvalidInputError on non-decodable base64 under data" do
      yaml = "apiVersion: v1\nkind: Secret\n" \
             "metadata: { name: x, namespace: a }\ndata: { k: '@@@' }\n"
      expect { described_class.from_buffer(yaml) }
        .to raise_error(RKSeal::InvalidInputError, /not valid base64/)
    end
  end

  describe "#to_buffer" do
    subject(:secret) do
      described_class.new(name: "db", namespace: "app", data: { "user" => b64("alice") })
    end

    it "renders a full Secret manifest with data shown as base64 verbatim" do
      doc = YAML.safe_load(secret.to_buffer)
      expect(doc).to include(
        "apiVersion" => "v1", "kind" => "Secret", "type" => "Opaque",
        "data" => { "user" => b64("alice") }
      )
      expect(doc.dig("metadata", "name")).to eq("db")
    end

    it "includes an explanatory commented header when commented: true" do
      expect(secret.to_buffer(commented: true)).to start_with("# rkseal:")
    end

    it "shows a concrete worked stringData example in the commented header" do
      header = secret.to_buffer(commented: true).lines.take_while { |l| l.start_with?("#") }.join
      expect(header).to match(/#\s+stringData:/)
      expect(header).to match(/#\s+\w+: .*plaintext/)
    end

    it "keeps the worked-example header as comments only (parses to a valid Secret)" do
      expect(described_class.from_buffer(secret.to_buffer(commented: true))).to eq(secret)
    end

    it "omits the comment header by default (round-tripping)" do
      expect(secret.to_buffer).not_to start_with("#")
    end

    it "round-trips through from_buffer to an equal Secret" do
      expect(described_class.from_buffer(secret.to_buffer)).to eq(secret)
    end

    context "with reveal: true" do
      subject(:secret) do
        described_class.new(name: "db", namespace: "app",
                            data: { "user" => b64("alice"), "pw" => b64("s3cr3t") })
      end

      it "decodes data and emits it as plaintext stringData (no data block)" do
        doc = YAML.safe_load(secret.to_buffer(reveal: true))
        expect(doc.fetch("stringData")).to eq("user" => "alice", "pw" => "s3cr3t")
        expect(doc).not_to have_key("data")
      end

      it "round-trips: a revealed buffer re-parses to the same Secret" do
        expect(described_class.from_buffer(secret.to_buffer(reveal: true))).to eq(secret)
      end

      it "still shows an empty stringData block for a secret with no data" do
        empty = described_class.seed(name: "db", namespace: "app")
        expect(YAML.safe_load(empty.to_buffer(reveal: true))).to include("stringData" => {})
      end

      it "raises InvalidInputError when a stored data value is not valid base64" do
        malformed = described_class.new(name: "db", namespace: "app",
                                        data: { "k" => "!!!not-base64" })
        expect { malformed.to_buffer(reveal: true) }
          .to raise_error(RKSeal::InvalidInputError, /not valid base64/)
      end
    end

    context "with string_data: true (editor plaintext switch)" do
      subject(:secret) do
        described_class.new(name: "db", namespace: "app", data: { "user" => b64("alice") })
      end

      it "decodes data to plaintext stringData, same as reveal" do
        doc = YAML.safe_load(secret.to_buffer(string_data: true))
        expect(doc.fetch("stringData")).to eq("user" => "alice")
        expect(doc).not_to have_key("data")
      end
    end
  end

  describe "#to_manifest" do
    subject(:secret) do
      described_class.new(name: "db", namespace: "app", data: { "user" => b64("alice") },
                          metadata: { "labels" => { "app" => "db" } })
    end

    it "emits clean base64 data (kubeseal handles it; no hand-rolled stringData)" do
      doc = YAML.safe_load(secret.to_manifest)
      expect(doc.fetch("data")).to eq("user" => b64("alice"))
      expect(doc).not_to have_key("stringData")
    end

    it "carries name, namespace, type, and author metadata for kubeseal to derive the template" do
      doc = YAML.safe_load(secret.to_manifest)
      expect(doc.dig("metadata", "name")).to eq("db")
      expect(doc.dig("metadata", "namespace")).to eq("app")
      expect(doc.dig("metadata", "labels")).to eq("app" => "db")
      expect(doc.fetch("type")).to eq("Opaque")
    end

    it "does NOT inject a scope annotation (scope is applied by kubeseal --scope)" do
      annotations = YAML.safe_load(secret.to_manifest(scope: :cluster_wide)).dig("metadata",
                                                                                 "annotations")
      expect(annotations).to be_nil
    end

    it "accepts every known scope" do
      %i[strict namespace_wide cluster_wide].each do |scope|
        expect { secret.to_manifest(scope: scope) }.not_to raise_error
      end
    end

    it "raises InvalidInputError for an unknown scope" do
      expect { secret.to_manifest(scope: :galaxy_wide) }
        .to raise_error(RKSeal::InvalidInputError, /unknown scope/)
    end
  end

  describe "#with_value" do
    subject(:secret) { described_class.seed(name: "db", namespace: "app") }

    it "returns a NEW Secret with one item set from file contents, base64-encoded" do
      result = secret.with_value(key: "user", contents: "alice")
      expect(result.data).to eq("user" => b64("alice"))
      expect(secret).to be_empty
    end

    it "is binary-safe (round-trips arbitrary bytes)" do
      bytes = (0..255).map(&:chr).join
      result = secret.with_value(key: "blob", contents: bytes)
      expect(Base64.strict_decode64(result.data.fetch("blob"))).to eq(bytes)
    end

    it "overwrites an existing key" do
      seeded = secret.with_value(key: "k", contents: "old")
      expect(seeded.with_value(key: "k", contents: "new").data).to eq("k" => b64("new"))
    end
  end

  describe "#validate!" do
    it "passes for an Opaque Secret with at least one item" do
      secret = described_class.new(name: "db", namespace: "app", data: { "k" => b64("v") })
      expect { secret.validate! }.not_to raise_error
    end

    it "raises InvalidInputError when there are no data items" do
      expect { described_class.seed(name: "db", namespace: "app").validate! }
        .to raise_error(RKSeal::InvalidInputError, /no data items/)
    end

    it "requires tls.crt and tls.key for kubernetes.io/tls" do
      secret = described_class.new(name: "t", namespace: "app", type: "kubernetes.io/tls",
                                   data: { "tls.crt" => b64("cert") })
      expect { secret.validate! }
        .to raise_error(RKSeal::InvalidInputError, /tls\.key/)
    end

    it "requires .dockerconfigjson for kubernetes.io/dockerconfigjson" do
      secret = described_class.new(name: "d", namespace: "app",
                                   type: "kubernetes.io/dockerconfigjson",
                                   data: { "other" => b64("x") })
      expect { secret.validate! }
        .to raise_error(RKSeal::InvalidInputError, /\.dockerconfigjson/)
    end

    it "passes a complete TLS Secret" do
      secret = described_class.new(name: "t", namespace: "app", type: "kubernetes.io/tls",
                                   data: { "tls.crt" => b64("c"), "tls.key" => b64("k") })
      expect { secret.validate! }.not_to raise_error
    end
  end

  describe "#empty?" do
    it "is true when there are no data items" do
      expect(described_class.seed(name: "db", namespace: "app")).to be_empty
    end

    it "is false once an item is present" do
      expect(described_class.new(name: "db", namespace: "app",
                                 data: { "k" => b64("v") })).not_to be_empty
    end
  end

  describe "#== (no-op detection)" do
    let(:base) do
      described_class.new(name: "db", namespace: "app", data: { "user" => b64("alice") },
                          metadata: { "labels" => { "app" => "db" } })
    end

    it "is equal to another Secret with the same author-owned fields" do
      twin = described_class.new(name: "db", namespace: "app", data: { "user" => b64("alice") },
                                 metadata: { "labels" => { "app" => "db" } })
      expect(base).to eq(twin)
    end

    it "treats a plaintext stringData edit equal to the matching base64 data" do
      via_string = described_class.from_buffer(<<~YAML)
        apiVersion: v1
        kind: Secret
        type: Opaque
        metadata: { name: db, namespace: app, labels: { app: db } }
        stringData: { user: alice }
      YAML
      expect(via_string).to eq(base)
    end

    it "differs when a data value changes" do
      changed = described_class.new(name: "db", namespace: "app", data: { "user" => b64("bob") },
                                    metadata: { "labels" => { "app" => "db" } })
      expect(base).not_to eq(changed)
    end

    it "differs when metadata changes" do
      changed = described_class.new(name: "db", namespace: "app", data: { "user" => b64("alice") })
      expect(base).not_to eq(changed)
    end

    it "is not equal to a non-Secret" do
      expect(base).not_to eq("db")
    end

    it "hashes consistently with equality" do
      twin = described_class.new(name: "db", namespace: "app", data: { "user" => b64("alice") },
                                 metadata: { "labels" => { "app" => "db" } })
      expect(base.hash).to eq(twin.hash)
    end
  end
end
