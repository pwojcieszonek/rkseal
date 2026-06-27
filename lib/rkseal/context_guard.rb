# frozen_string_literal: true

require "thor"

module RKSeal
  # Gatekeeper for the one genuinely dangerous operation: deploying to a
  # cluster. Applying a SealedSecret to the wrong context can clobber another
  # environment, so a deploy must be explicitly confirmed by the operator.
  #
  # rkseal always operates on the *current* kube context -- there is no
  # allow-list. The guard's job is narrow: surface the active context and ask
  # the operator to confirm before {RKSeal::Kubectl#apply} runs. Deploy is never
  # the default for `edit`; this class enforces the "explicit + confirmed"
  # requirement via an interactive yes/no prompt that defaults to No.
  #
  # This class does NOT shell out itself -- it delegates to the injected
  # {RKSeal::Kubectl} for the context name and to a Thor shell for the prompt.
  class ContextGuard
    # @param kubectl [RKSeal::Kubectl] adapter used to read the active context.
    # @param prompt [Thor::Shell::Basic] shell used for the interactive
    #   confirmation; injected so specs can drive #yes? without real stdin.
    def initialize(kubectl:, prompt: Thor::Shell::Basic.new)
      @kubectl = kubectl
      @prompt = prompt
    end

    # The current kube context, as reported by kubectl.
    #
    # @return [String]
    # @raise [RKSeal::CommandError] if kubectl cannot report a context.
    def current_context
      @kubectl.current_context
    end

    # Surface the active context and ask the operator to confirm the deploy.
    # Called immediately before {RKSeal::Kubectl#apply}; the apply happens only
    # when this returns true. The prompt defaults to No, so an empty answer (or a
    # non-interactive run) declines.
    #
    # @param secret_name [String] the SealedSecret's name, for the prompt.
    # @param namespace [String] the target namespace, for the prompt.
    # @return [Boolean] whether the operator approved the deploy.
    # @raise [RKSeal::CommandError] if kubectl cannot report a context.
    #
    # rubocop:disable Naming/PredicateMethod -- this is an action ("ask and
    # apply-or-not"), not a query; its name is a frozen part of the public API
    # that the command layer codes against, so it cannot take a `?` suffix.
    def confirm_deploy(secret_name:, namespace:)
      context = current_context
      @prompt.yes?(
        "Deploy #{secret_name.inspect} (namespace #{namespace.inspect}) " \
        "to context #{context.inspect}? [y/N]"
      )
    end
    # rubocop:enable Naming/PredicateMethod
  end
end
