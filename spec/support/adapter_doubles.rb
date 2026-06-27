# frozen_string_literal: true

# Reusable stubbing pattern for the external-binary adapters.
#
# rkseal's command flows take their collaborators as keyword arguments
# (`kubeseal:`, `kubectl:`, `editor:`, `context_guard:`), so unit specs inject
# verified instance doubles instead of touching a real cluster or `$EDITOR`.
# `verify_partial_doubles` (set in spec_helper) ensures these doubles can only
# stub methods that actually exist on the adapter classes, so the contracts and
# the tests cannot drift apart.
#
# Usage in a spec:
#
#   include AdapterDoubles
#
#   let(:kubeseal) { fake_kubeseal(seal: "kind: SealedSecret\n") }
#   let(:kubectl)  { fake_kubectl(get_secret: secret_json) }
#
#   subject(:command) do
#     RKSeal::Commands::Edit.new(
#       namespace: "app", name: "db",
#       kubeseal: kubeseal, kubectl: kubectl, editor: fake_editor
#     )
#   end
#
# Each helper returns an `instance_double` with no-op-ish defaults; override any
# return value via keyword args. Devs extend these as the contracts solidify.
module AdapterDoubles
  # @param overrides [Hash] method => return value (or use a block on the
  #   resulting double for richer stubbing).
  # @return [RSpec::Mocks::InstanceVerifyingDouble] a fake RKSeal::Kubeseal.
  def fake_kubeseal(**overrides)
    instance_double(RKSeal::Kubeseal, **default_kubeseal, **overrides)
  end

  # @return [RSpec::Mocks::InstanceVerifyingDouble] a fake RKSeal::Kubectl.
  def fake_kubectl(**overrides)
    instance_double(RKSeal::Kubectl, **default_kubectl, **overrides)
  end

  # @return [RSpec::Mocks::InstanceVerifyingDouble] a fake RKSeal::Editor.
  def fake_editor(**overrides)
    instance_double(RKSeal::Editor, **default_editor, **overrides)
  end

  # @return [RSpec::Mocks::InstanceVerifyingDouble] a fake RKSeal::ContextGuard.
  def fake_context_guard(**overrides)
    instance_double(RKSeal::ContextGuard, **default_context_guard, **overrides)
  end

  # A stand-in for the block-scoped {RKSeal::SecureWorkspace.with} that the
  # command flows use to obtain a RAM-backed scratch path. It is a plain object
  # (not an instance_double) because the real collaborator is a *class* method;
  # it yields a path under an on-disk tmpdir so unit specs never attach a real
  # RAM disk, while still exercising the editor-on-a-path code path.
  #
  # @param path [String, nil] the path to yield; a fresh tmpfile when nil.
  # @return [Object] something that responds to `.with(basename:) { |path| ... }`.
  def fake_workspace(path: nil)
    FakeWorkspace.new(path)
  end

  # Records how many times it was entered and the last basename, so specs can
  # assert the workspace was actually used (no plaintext-on-real-disk guarantee
  # is delegated to the real SecureWorkspace's own spec).
  class FakeWorkspace
    attr_reader :calls, :last_basename

    def initialize(path)
      @path = path
      @calls = 0
      @last_basename = nil
    end

    def with(basename: "rkseal")
      @calls += 1
      @last_basename = basename
      path = @path || File.join(Dir.mktmpdir, "#{basename}-buffer")
      yield path
    end
  end

  private

  def default_kubeseal
    {
      ensure_available!: nil,
      ensure_cert!: nil,
      seal: "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\n",
      validate: true,
      fetch_cert: "-----BEGIN CERTIFICATE-----\n",
      merge_into: nil,
      re_encrypt: "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\n# re-encrypted\n"
    }
  end

  def default_kubectl
    {
      ensure_available!: nil,
      get_secret: "{}",
      get_sealedsecret: "{}",
      list_sealedsecrets: '{"items":[]}',
      apply: "sealedsecret.bitnami.com/example configured",
      current_context: "docker-desktop"
    }
  end

  def default_editor
    {
      resolve_command: "true",
      edit: ""
    }
  end

  # New ContextGuard contract (Phase 3): no allow-list -- it surfaces the active
  # context and confirms the deploy interactively. confirm_deploy defaults to
  # true so the happy path deploys; override to false to exercise a decline.
  def default_context_guard
    {
      current_context: "docker-desktop",
      confirm_deploy: true
    }
  end
end
