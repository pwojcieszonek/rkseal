# frozen_string_literal: true

RSpec.describe "RKSeal error hierarchy" do
  describe "hierarchy" do
    it "roots every deliberate error at RKSeal::Error" do
      [
        RKSeal::DependencyMissingError,
        RKSeal::CommandError,
        RKSeal::NotFoundError,
        RKSeal::InvalidInputError,
        RKSeal::WorkspaceError,
        RKSeal::EditorError
      ].each do |klass|
        expect(klass.ancestors).to include(RKSeal::Error)
      end
    end

    it "descends RKSeal::Error from StandardError (so a bare rescue catches it)" do
      expect(RKSeal::Error.ancestors).to include(StandardError)
    end
  end

  describe RKSeal::CommandError do
    it "carries command label, exit status, and scrubbed stderr" do
      error = described_class.new("boom", command: "kubeseal seal", status: 1, stderr: "nope")

      expect(error.command).to eq("kubeseal seal")
      expect(error.status).to eq(1)
      expect(error.stderr).to eq("nope")
      expect(error.message).to eq("boom")
    end
  end
end
