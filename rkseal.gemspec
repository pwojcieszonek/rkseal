# frozen_string_literal: true

require_relative "lib/rkseal/version"

Gem::Specification.new do |spec|
  spec.name = "rkseal"
  spec.version = RKSeal::VERSION
  spec.authors = ["Piotr Wojcieszonek"]
  spec.email = ["piotr@wojcieszonek.pl"]

  spec.summary = "Interactively create and edit Kubernetes SealedSecrets via $EDITOR."
  spec.description = <<~DESC
    rkseal wraps the kubeseal CLI to author and edit Kubernetes SealedSecrets.
    The plaintext Secret manifest is edited in $EDITOR on a RAM-backed buffer
    that never touches persistent disk, then sealed with the controller's public key.
    Deploys to the cluster are explicit opt-in only and guarded by the active kube context.
  DESC
  spec.homepage = "https://github.com/pwojcieszonek/rkseal"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 4.0.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["rubygems_mfa_required"] = "true"

  # Files are listed explicitly to avoid depending on a git index (the gem may be
  # built from a non-git export). Keep this in sync with the project layout.
  spec.files = Dir[
    "lib/**/*.rb",
    "exe/*",
    "README.md",
    "LICENSE.txt",
    "rkseal.gemspec"
  ]
  spec.bindir = "exe"
  spec.executables = ["rkseal"]
  spec.require_paths = ["lib"]

  # Runtime dependency: the CLI framework.
  spec.add_dependency "thor", "~> 1.3"

  # base64 left the default gems in Ruby 3.4; on 4.0.2 it is no longer on the
  # load path under `bundle exec` unless declared. RKSeal::Secret requires it
  # for the base64 <-> plaintext data conversions, so it must be a runtime dep.
  # (open3, also required by the adapters, is still a bundled default gem on
  # 4.0.2 and loads cleanly under bundle exec, so it is intentionally not pinned.)
  spec.add_dependency "base64", "~> 0.2"

  # Development dependencies. Versions are intentionally left as compatible ranges
  # rather than hard pins until the toolchain is proven on Ruby 4.0.2.
  spec.add_development_dependency "rspec", "~> 3.13"
  spec.add_development_dependency "rubocop", "~> 1.60"
end
