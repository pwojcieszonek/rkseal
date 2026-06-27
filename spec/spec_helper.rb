# frozen_string_literal: true

require "tmpdir"
require "fileutils"
require "rkseal"

# Load shared support (fake adapters, helpers) for every spec.
Dir[File.join(__dir__, "support", "**", "*.rb")].each { |file| require file }

RSpec.configure do |config|
  config.expect_with :rspec do |expectations|
    expectations.include_chain_clauses_in_custom_matcher_descriptions = true
  end

  config.mock_with :rspec do |mocks|
    mocks.verify_partial_doubles = true
  end

  config.shared_context_metadata_behavior = :apply_to_host_groups
  config.filter_run_when_matching :focus
  config.example_status_persistence_file_path = "spec/examples.txt"
  config.disable_monkey_patching!
  config.warnings = true
  config.order = :random
  Kernel.srand config.seed

  # Hard guard: unit specs must never shell out to a real cluster or binary.
  # Implementation specs that genuinely need to exercise the runner can opt out
  # with `:allow_exec`. Anything else that reaches a process-spawning call fails
  # loudly, so a stub gap can't silently hit kubeseal/kubectl/$EDITOR.
  #
  # The adapters funnel every invocation through `Open3.capture3`, but a stray
  # test (or a future adapter) could reach for any of the other spawn paths, so
  # we fence off the whole family: the Kernel sugar (`` ` ``, `system`, `exec`)
  # *and* the explicit spawn APIs (`Open3.capture2/2e/3/popen3`,
  # `Process.spawn`, `IO.popen`). Each is a singleton/class method, so we stub
  # the receiver object directly rather than `allow_any_instance_of`.
  config.before do |example|
    next if example.metadata[:allow_exec]

    # Kernel-level sugar mixed into every object. `exec` replaces the current
    # process, so an unstubbed call would terminate the test runner outright --
    # all the more reason to fence it.
    [Kernel, Object].each do |mod|
      allow_any_instance_of(mod).to receive(:`) do |_, cmd|
        raise "Unit spec attempted to shell out (backtick): #{cmd.inspect}. Stub the adapter."
      end
      allow_any_instance_of(mod).to receive(:system) do |_, *cmd|
        raise "Unit spec attempted to system(): #{cmd.inspect}. Stub the adapter."
      end
      allow_any_instance_of(mod).to receive(:exec) do |_, *cmd|
        raise "Unit spec attempted to exec(): #{cmd.inspect}. Stub the adapter."
      end
    end

    # Explicit process-spawning library/class methods (module functions and
    # singleton methods). `capture2e` and `popen2/2e/3` round out the Open3
    # surface so no variant slips through.
    %i[capture2 capture2e capture3 popen2 popen2e popen3].each do |meth|
      allow(Open3).to receive(meth) do |*cmd|
        raise "Unit spec attempted Open3.#{meth}: #{cmd.inspect}. Stub the adapter's runner."
      end
    end

    allow(Process).to receive(:spawn) do |*cmd|
      raise "Unit spec attempted Process.spawn: #{cmd.inspect}. Stub the adapter."
    end

    allow(IO).to receive(:popen) do |*cmd|
      raise "Unit spec attempted IO.popen: #{cmd.inspect}. Stub the adapter."
    end
  end
end
