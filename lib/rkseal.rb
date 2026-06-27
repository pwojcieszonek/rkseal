# frozen_string_literal: true

require_relative "rkseal/version"

# Top-level namespace for the rkseal gem.
#
# rkseal wraps the `kubeseal` CLI to create and edit Kubernetes SealedSecrets
# interactively via `$EDITOR`, in the spirit of `knife vault create/edit`.
#
# == Layer map (one file per layer; each is independently testable/mockable)
#
# Foundation:
#   RKSeal::Errors            -- error hierarchy for fail-fast behavior
#                                (errors.rb)
#
# Domain:
#   RKSeal::Secret            -- build/parse the k8s Secret manifest, base64
#                                encode/decode, strip runtime metadata, convert
#                                between cluster JSON and the edit buffer
#                                (secret.rb)
#   RKSeal::SealedSecret      -- read a local SealedSecret's keys/scope/type and
#                                render the redacted `edit --local` buffer
#                                (sealed_secret.rb)
#
# External-binary adapters (shell out; stubbed in unit tests):
#   RKSeal::Kubeseal          -- adapter over `kubeseal` (seal/fetch_cert/
#                                merge_into/re_encrypt); owns scope/cert/
#                                controller flags (kubeseal.rb)
#   RKSeal::Kubectl           -- adapter over `kubectl` (get_secret/apply/
#                                current_context) (kubectl.rb)
#   RKSeal::Editor            -- launch `$EDITOR` on a buffer, return edited
#                                content (editor.rb)
#
# Environment / safety:
#   RKSeal::SecureWorkspace   -- per-OS RAM-backed scratch path with guaranteed
#                                teardown (secure_workspace.rb)
#   RKSeal::ContextGuard      -- enforce which kube context deploys are allowed
#                                against (context_guard.rb)
#
# Orchestration:
#   RKSeal::Commands::Result  -- shared command-outcome value object
#                                (commands/result.rb)
#   RKSeal::Commands::Create  -- the `create` flow (commands/create.rb)
#   RKSeal::Commands::Edit    -- the `edit` flow (commands/edit.rb)
#   RKSeal::Commands::EditLocal -- the offline `edit --local` flow
#                                (commands/edit_local.rb)
#   RKSeal::Commands::Reencrypt -- the `reencrypt` flow (commands/reencrypt.rb)
#   RKSeal::Commands::Validate  -- the `validate` flow (commands/validate.rb)
#   RKSeal::Commands::View      -- the `view` flow (commands/view.rb)
#   RKSeal::Commands::List      -- the `list` flow (commands/list.rb)
#   RKSeal::CLI               -- Thor command parsing & dispatch (cli.rb)
#
# == Require layout
#
# Requires are listed explicitly and ordered from leaves to roots so the
# dependency graph loads without surprises (errors and the domain model first,
# adapters and environment helpers next, orchestration last). Each layer lives
# in exactly one file, so the three implementation agents edit disjoint files
# and never need to co-edit this one. Adding a brand-new layer is the only
# reason to touch this file again.
module RKSeal
end

# Foundation.
require_relative "rkseal/errors"

# Domain models.
require_relative "rkseal/secret"
require_relative "rkseal/sealed_secret"

# External-binary adapters.
require_relative "rkseal/kubeseal"
require_relative "rkseal/kubectl"
require_relative "rkseal/editor"

# Environment / safety helpers.
require_relative "rkseal/secure_workspace"
require_relative "rkseal/context_guard"

# Orchestration (commands depend on everything above; CLI depends on commands).
require_relative "rkseal/commands/result"
require_relative "rkseal/commands/create"
require_relative "rkseal/commands/edit"
require_relative "rkseal/commands/edit_local"
require_relative "rkseal/commands/reencrypt"
require_relative "rkseal/commands/validate"
require_relative "rkseal/commands/view"
require_relative "rkseal/commands/list"
require_relative "rkseal/cli"
