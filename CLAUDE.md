# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`rkseal` is a Ruby gem that wraps the `kubeseal` CLI to create and edit Kubernetes
[Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets) interactively, in the
spirit of `knife vault create/edit`. Six commands:

```
rkseal create    <namespace> <secret-name>   # author a new sealed secret
rkseal edit      <namespace> <secret-name>   # edit an existing one (auto-offline if not on cluster)
rkseal reencrypt <namespace> <secret-name>   # rotate onto the controller's current key
rkseal validate  [<namespace> <secret-name>] # controller pre-flight check (--file <path>)
rkseal view      <namespace> <secret-name>   # print the live Secret (--reveal to decode)
rkseal list      [<namespace>]               # list SealedSecrets (metadata only)
```

`create`/`edit` open the secret's plaintext in `$EDITOR` for interactive editing (or skip the
editor with `--no-edit` when values are pre-seeded via `--from-file`). The resulting
`SealedSecret` manifest is written to the **current working directory**. `edit` and
`reencrypt` can optionally deploy the change to the cluster, but deploying is **never the
default** — it is an explicit opt-in flag. `validate`, `view`, and `list` are read-only.

**Status: shipped (MVP complete).** All six commands are implemented, the full RSpec suite is
green, and RuboCop is clean. The sections below describe the architecture as built and the
hard constraints it respects. They also encode domain knowledge (how Sealed Secrets actually
work) that is non-obvious and easy to get wrong.

## Domain background: how Sealed Secrets work (read before coding)

A `SealedSecret` is encrypted with the controller's **public** key. The matching
**private** key never leaves the cluster — by design there are *no backdoors*. This single
fact drives the whole architecture:

- **You cannot decrypt a SealedSecret client-side.** To show a user the *current* values
  of an existing secret (the `edit` flow), the only source of truth is the **unsealed
  `Secret`** that the controller materialised in the cluster:
  `kubectl get secret <name> -n <ns> -o json`, then base64-decode `.data`.
  Reading the local `*.yaml` SealedSecret file is useless for recovering plaintext.
- **`--merge-into` and `--raw` do not decrypt anything.** `kubeseal --merge-into <file>`
  appends freshly-encrypted items to an existing SealedSecret without knowing the old
  cleartext; `--raw` encrypts a single value. These are *blind* updates — useful as a
  fallback, but they cannot drive a "show current values, let the user edit them" UX.

### Scopes (critical — wrong scope = silent decryption failure)

The scope decides whether `name`/`namespace` are bound into the ciphertext:

| Scope | Binding | Annotation / flag |
|-------|---------|-------------------|
| `strict` (default) | name **and** namespace are part of the encrypted data; cannot be renamed or moved | none (default) |
| `namespace-wide` | namespace locked, name free | `sealedsecrets.bitnami.com/namespace-wide: "true"` or `--scope namespace-wide` |
| `cluster-wide` | any name, any namespace | `sealedsecrets.bitnami.com/cluster-wide: "true"` or `--scope cluster-wide` |

Because `rkseal create <namespace> <secret-name>` takes name and namespace as positional
args, the default `strict` scope is the natural fit; scope must be selectable (flag and/or
annotation on the input Secret).

### SealedSecret resource shape

```yaml
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: mysecret
  namespace: mynamespace
spec:
  encryptedData:
    foo: AgBy3i4OJSWK+...        # opaque ciphertext per item
  template:                       # optional: shapes the resulting Secret (type, labels, ...)
    type: Opaque
```

### Public certificate

`kubeseal` needs the controller's cert to encrypt. Sources, in order of usefulness here:
`--cert <file|URL>` or the `SEALED_SECRETS_CERT` env var (offline — nothing contacted), else
`--fetch-cert` from the live controller. **The cert is never cached on disk.** When neither
offline source is configured, the cert is fetched fresh from the controller on every
invocation, so a seal is always bound to the *current context's* controller key. This is a
deliberate choice: a cross-invocation disk cache keyed only by `<controller-namespace>/
<controller-name>` (which is identical across clusters — `kube-system/sealed-secrets-controller`
is the default everywhere) silently served one cluster's public cert when sealing for another,
producing ciphertext the target controller could not decrypt (`no key could decrypt secret`).
It also went stale on controller rekey/reinstall. Fetching fresh costs one sub-second
`--fetch-cert` per invocation and removes both failure modes; GitOps/CI that wants offline,
reproducible seals pins `--cert`/`SEALED_SECRETS_CERT` instead (strictly better than a cache).

### Key rotation

Controllers rotate sealing keys (~30 days). Old keys still decrypt old SealedSecrets.
`rkseal reencrypt` (→ `kubeseal --re-encrypt`) rotates a SealedSecret onto the controller's
current key without exposing plaintext — shipped; see the `reencrypt` flow below.

## Architecture

A clean separation between *orchestration* (the command flows) and *adapters* (thin wrappers
over external binaries) — each independently testable and mockable:

- `RKSeal::CLI` — argument/command parsing, dispatch, DNS-1123 name/namespace validation.
- `RKSeal::Commands::{Create,Edit,EditLocal,Reencrypt,Validate,View,List}` — orchestrate one
  flow each (`EditLocal` is the offline `edit --local`; see below).
- `RKSeal::Kubeseal` — adapter over the `kubeseal` binary (`ensure_cert!`, `seal`,
  `fetch_cert`, `re_encrypt`, `validate`). Owns scope/cert/controller flags. `ensure_cert!` is
  a fail-fast reachability probe (`--fetch-cert`, result discarded); the cert is never cached —
  `seal` re-fetches fresh each time (or passes an explicit `--cert`).
- `RKSeal::Kubectl` — adapter over `kubectl` (`get_secret`, `apply`, `current_context`).
- `RKSeal::Editor` — launches `$EDITOR` on a buffer and returns the edited content.
- `RKSeal::SecureWorkspace` — provides the **in-memory** scratch file (see constraints) and
  guarantees its destruction.
- `RKSeal::Secret` — domain model: build the k8s `Secret` manifest, base64 encode/decode,
  convert between the cluster representation and the friendly key→value edit buffer.
- `RKSeal::SealedSecret` — domain model for the *SealedSecret* resource: read a local
  `<name>.yaml`'s data **keys** (the map keys are plaintext), scope annotation, and template
  `type`, and render the *redacted* `edit --local` buffer. It never decrypts anything.
- `RKSeal::ContextGuard` — surfaces the active kube context before a deploy and asks the
  operator to confirm it (no allow-list; `--yes` skips the prompt for pipelines).

### `create` flow

1. Pre-resolve the controller cert up front (`--cert`/env, else `--fetch-cert`) — fail fast
   before opening the editor if it cannot be obtained.
2. Open an ephemeral buffer in `$EDITOR` seeded with a commented template — an empty `data`
   (base64) block by default, or an empty `stringData` (plaintext) block with `--string-data`.
3. Parse the saved buffer into items (base64 `data` and/or plaintext `stringData`, folded into
   one base64 `data` map with `stringData` winning per key).
4. Build a `Secret` manifest (base64 `data`; `stringData` was folded in on parse) plus the
   scope annotation if non-strict.
5. Pipe it through `kubeseal --scope <scope> [--cert …]` to produce the SealedSecret.
6. Write the SealedSecret to the current directory.
7. Destroy the buffer.

### `edit` flow

0. **Source precedence (the local `<name>.yaml` is the working copy).** `edit` writes to the
   local file but reads decrypted values from the cluster, so a non-deployed edit makes the two
   diverge. To keep read/write consistent and never silently discard un-deployed work, `edit`
   chooses its source like this (all without `--local`):
   - **No local file** → seed from the cluster (step 1); its `NotFound` ⇒ **fail fast** → `create`.
   - **Local file present, payload == the deployed SealedSecret** (no un-deployed changes; after a
     deploy the file is byte-identical to the cluster object) → seed from the cluster (full,
     decrypted values).
   - **Local file present, payload diverges, or the SealedSecret is absent from the cluster**
     (un-deployed changes, or "created but never deployed") → **edit the local file offline**
     (the redacted keep/reseal/remove flow below), with a one-line notice. After you `--deploy`,
     the file matches the cluster again and full values come back.
   Divergence is detected by comparing the local file's `spec.encryptedData`/`template` against
   `kubectl get sealedsecret` (`RKSeal::SealedSecret.diverged?`) — no decryption. The probe runs
   only when a local file exists; an *unreachable* cluster (an error other than `NotFound`) is
   surfaced as-is (use `--local` to force offline). `--local` always forces the offline path.
1. `kubectl get secret <name> -n <ns> -o json` → base64-decode `.data` into the plaintext
   key→value map. **This is the only way to recover current values.** A cluster-present edit
   never falls back to a blind `--merge-into`.
2. Open the map in `$EDITOR` (ephemeral buffer).
3. Re-seal the edited map (same as `create` steps 4–6) and write to the current directory.
   **Scope is preserved**: read the existing SealedSecret's scope annotation from the cluster
   (falling back to the local `<name>.yaml`, then to `strict`); `--scope` overrides. If the
   buffer is unchanged, this is a no-op — write nothing and produce no fresh ciphertext.
4. **Only if** `--deploy` is passed: surface the active context via `ContextGuard` and ask the
   operator to confirm (`--yes` skips the prompt for pipelines), then `kubectl apply -f <file>`.
   Default is to write the file and stop.
5. Destroy the buffer.

### offline local edit flow (`edit --local`, or auto-fallback)

The standard `edit` recovers current values from the cluster Secret — impossible for a
SealedSecret authored with `create` but **never deployed** (no unsealed Secret exists). This
flow handles that case **without ever reading cluster state**, exploiting the one readable
fact about a SealedSecret: its `spec.encryptedData` **keys are plaintext** (only the values are
ciphertext). It is reached two ways: **automatically** when `edit` finds no cluster Secret but
a local `<name>.yaml` (no flag), or **explicitly** via `--local` (forces offline, never
contacts the cluster — for an unreachable cluster). `Commands::EditLocal` is the implementation
for both.

1. Source the local `<name>.yaml` (via `RKSeal::SealedSecret.parse`); if absent, **fail fast**
   and point at `create`. The cluster is **not** contacted for state.
2. Open a **redacted** buffer in `$EDITOR`: a `Secret` manifest where every existing key is
   shown as the literal `<redacted>` (the value cannot be decrypted) — under `data` (base64) by
   default, or under `stringData` (plaintext) with `--string-data`. The placeholder is honoured
   in either block.
3. Classify the saved buffer per key:
   - **keep** — value left as `<redacted>` → the existing ciphertext is left **byte-for-byte
     untouched** (no rehash; no plaintext needed);
   - **reseal** — value replaced, or a brand-new key added → sealed and merged in via
     `kubeseal --merge-into` (a *blind* merge that touches only those keys);
   - **remove** — an existing key deleted from the buffer → dropped from `spec.encryptedData`.
   `type` may be edited (→ `spec.template.type`). A new key left as `<redacted>`, an empty
   value, a renamed/moved secret, or an empty result all **fail fast**. An all-keep buffer is a
   no-op (nothing written).
4. **Hard constraints unique to this flow:** scope is **preserved** from the existing file and
   `--scope` is **rejected** (kept ciphertext cannot be re-sealed under a new scope without its
   plaintext); `name`/`namespace` are fixed (strict ciphertext binds them, and they are shared
   with the kept entries).
5. The cluster is touched **only** when a reseal is actually needed — and then only to fetch the
   controller's **public** cert (unless `--cert`/env supplies it offline). The file is re-emitted as
   YAML: `kubeseal --merge-into` (v0.36.6) rewrites it as JSON regardless of input format, so
   `EditLocal` normalizes it back so a `.yaml` always holds YAML.
6. `--deploy`/`--yes` behave exactly like `edit` (opt-in, `ContextGuard`-gated).

### `reencrypt` flow

Operates on the **SealedSecret itself** (no plaintext, so no editor and no RAM workspace):

1. Source the SealedSecret: local `<name>.yaml` if present, else the live SealedSecret from
   the cluster. If neither exists, **fail fast** and point at `create`.
2. `kubeseal --re-encrypt` rotates it onto the controller's current sealing key; write the
   result back to `<name>.yaml`.
3. Deploy exactly like `edit`: `--deploy` surfaces the active context and confirms (`--yes`
   skips the prompt); never the default.

### `validate` flow (read-only)

1. Pick the manifest: `--file <path>` if given, else the local `<name>.yaml` for the
   namespace/name (which are then optional positionals).
2. `kubeseal --validate` asks the controller whether it is well-formed and decryptable for its
   target. **Nothing is decrypted or revealed.** Prints `valid` and exits 0 on success;
   prints the reason and exits non-zero if the controller rejects it. A safe pre-flight before
   commit/apply.

### `view` flow (read-only)

1. `kubectl get secret <name> -n <ns> -o json`; if absent, **fail fast** and point at `create`.
2. Print the full Secret manifest to STDOUT — no editor, no RAM workspace, no file written.
   `data` is shown as raw base64 by default; `--reveal` decodes the values and prints them as
   plaintext `stringData` (opt-in, since it puts secrets on STDOUT).

### `list` flow (read-only)

1. `kubectl get sealedsecrets` (optionally scoped to `[namespace]`, else across all
   namespaces).
2. Print a table of columns `NAMESPACE`, `NAME`, `SCOPE`, `AGE`. **Metadata-only**: never any
   `encryptedData`/`data` — no editor, no RAM workspace, no file written.

## Critical constraints

- **Plaintext must never touch persistent disk.** The edit buffer lives in memory only.
  `SecureWorkspace` abstracts a **per-OS RAM-backed path** behind one interface:
  - **Linux** — tmpfs path (`/dev/shm`, or `$XDG_RUNTIME_DIR`).
  - **macOS** — an ephemeral `hdiutil`-backed RAM disk, attached for the duration of the
    edit and detached afterwards. macOS has no tmpfs / `/dev/shm`, so this is the price of
    honouring the requirement. **Never** fall back to a regular `mktemp` file on disk.
  - Whatever the medium: best-effort overwrite/shred and unlink, then detach/teardown the
    RAM disk on exit — including on error/signal (wrap in `ensure`/`at_exit` + signal trap,
    so a crashed RAM disk does not leak). Never log secret values.
  - **Editor side files are a real residual sink.** Some editors persist buffer contents
    *outside* the RAM-backed path (vim's swap file and viminfo register/mark history, an
    editor's autosave/backup), which would leak plaintext to persistent disk despite the
    workspace. `RKSeal::Editor` suppresses this for the vim family by injecting `-n` (no swap)
    and `-i NONE` (no viminfo) when the operator has not already set them. Editors it does not
    recognise pass through unchanged, so this remains a residual risk worth documenting for
    users of other editors.
- **Deploys are gated on the active context + confirmation.** Applying to the wrong cluster
  is the dangerous operation. rkseal operates on whatever context is current (no in-code
  allow-list); before any `kubectl apply` it surfaces that context and requires `--deploy`
  plus an interactive confirmation, with `--yes` to skip the prompt in pipelines. Deploy is
  never the default for `edit`.
- **Validate name/namespace before touching the filesystem or cluster.** Both positional args
  must be DNS-1123 labels; reject anything else (path-traversal like `../evil`, flag-injection
  like `-oyaml`) with an `InvalidInputError` and write no file.
- **Fail fast** on: missing `kubeseal`/`kubectl`, unreachable controller, unknown
  namespace, invalid name/namespace, empty edit buffer, malformed YAML from the editor.

## Environment & cluster (development)

- **Ruby 4.0.2**, managed with **rvm + a dedicated gemset**. Never install into system or
  global gemsets:
  ```
  rvm use 4.0.2@rkseal --create
  ```
  Run `bundle install` / `gem install` only after the gemset is active.
- `kubeseal` **v0.36.6** and `kubectl` are installed locally.
- **Dev/test-agent guardrail (not a product feature):** when an automated agent does cluster
  work in *this* environment, restrict it to the `docker-desktop` context — verify with
  `kubectl config current-context` first, and never touch the other contexts (`ekomat-test`,
  `tkk-k0s-prod`). The shipped tool itself has no such allow-list; it operates on whatever
  context is current and confirms before deploying (see Critical constraints).
- The sealed-secrets **controller is installed** on `docker-desktop` (controller + CRD in
  `kube-system`, from the upstream `controller.yaml`), so `kubeseal --fetch-cert` works there.
  A fresh cluster needs it installed first before integration testing.

## Development commands

Standard Ruby-gem workflows (all inside the active `4.0.2@rkseal` gemset):

```
bundle install                       # install dependencies
bundle exec exe/rkseal create ns name   # run the CLI from source
gem build rkseal.gemspec             # build the gem
bundle exec rspec                    # run the test suite
bundle exec rspec spec/foo_spec.rb:42   # run a single test / example
bundle exec rubocop                  # lint
```

Adapters (`Kubeseal`, `Kubectl`, `Editor`) shell out to external binaries — unit tests must
stub these so the suite runs without a cluster. Reserve real `kubeseal`/`kubectl` calls for
explicit integration tests gated on the `docker-desktop` context.

## Stack & decisions

Settled:
- **Ruby:** **4.0.2**, via **rvm + a dedicated `rkseal` gemset** (`.ruby-version` /
  `.ruby-gemset` committed). Never install into system/global gemsets.
- **CLI:** `Thor` (`~> 1.3`; resolves to 1.5.0 on Ruby 4.0.2) — idiomatic for
  sub-commands, with built-in prompts/colour.
- **Tests:** `RSpec` (`~> 3.13`), with `kubeseal`/`kubectl`/`$EDITOR` adapters stubbed.
  Adapters are constructor-injected so the suite never needs a real cluster.
- **Linter:** `RuboCop` (`~> 1.60`; resolves to 1.88.0), house style = double-quoted
  strings.
- **In-memory buffer:** per-OS RAM-backed path via `SecureWorkspace` (see constraints).
- **Editor buffer = a full Kubernetes `Secret` manifest** (not a custom key→value
  format). The user controls `data` vs `stringData`, `type`, and `metadata`
  (labels/annotations).
- **Buffer value block defaults to `data` (base64); `--string-data` switches to plaintext
  `stringData`.** This applies to `create` (empty seed block), cluster `edit` (base64 verbatim
  by default, or the live Secret decoded to plaintext with `--string-data` — an opt-in plaintext
  exposure), and the offline local edit (redacted keys under `data` vs `stringData`). On parse
  both blocks fold into one base64 `data` map (`stringData` wins per key). `view` keeps its own
  `--reveal` switch for the same plaintext presentation. The flag threads through as
  `string_data:` on `Secret#to_buffer`/`SealedSecret#to_buffer` and the command classes.
- **MVP scope = full (shipped):** Opaque + multiline values + load-value-from-file
  (`--from-file key=path`, repeatable, binary-safe) + `--no-edit` (seal the pre-seeded Secret
  without opening `$EDITOR`) + Secret `type`s (e.g. `kubernetes.io/tls`,
  `kubernetes.io/dockerconfigjson`) + `spec.template` (kubeseal derives it from the input
  Secret's `type`/`metadata`). On `edit`, the live Secret's `data` is shown as raw base64
  (verbatim, not decoded) by default; plaintext goes under `stringData`, and `--string-data`
  decodes the whole buffer to plaintext `stringData`.
- **Commands (shipped):** `create`, `edit` (incl. offline `--local`, see below), `reencrypt`
  (rotate onto the current key; `--deploy`/`--yes`), `validate` (controller
  pre-flight, read-only; `--file <path>`), `view` (print live Secret,
  read-only; `--reveal` decodes to plaintext `stringData`), `list` (read-only, metadata-only
  table of `NAMESPACE`/`NAME`/`SCOPE`/`AGE` across all namespaces or one `[namespace]`).
- **Offline local edit (never-deployed SealedSecret):** reached **automatically** when `edit`
  finds no cluster Secret but a local `<name>.yaml` (no flag), or forced with `--local` (never
  contacts the cluster — for an unreachable one). Operates on the local `<name>.yaml`: existing
  keys are shown `<redacted>`; keep (leave) / reseal (replace or add) / remove (delete) per key
  via `kubeseal --merge-into`; kept ciphertext stays byte-for-byte. Scope is preserved and
  `--scope` is rejected; name/namespace are fixed. Output is normalized back to YAML (merge-into
  emits JSON). The auto-fallback fires only on a definitive `NotFound`. See the offline local
  edit flow above and `RKSeal::Commands::EditLocal` / `RKSeal::SealedSecret`.
- **`create` cert handling:** the controller cert is pre-resolved up front (`--cert`/env, else
  a `--fetch-cert` probe) and fails fast before the editor opens.
- **No cert cache:** the public cert is never persisted on disk. With no offline source
  (`--cert`/`SEALED_SECRETS_CERT`) it is fetched fresh from the controller on every invocation,
  so every seal is bound to the *current context's* key. A disk cache keyed only by
  `<controller-namespace>/<controller-name>` collided across clusters (that path is identical
  everywhere) and went stale on rekey — it once produced ciphertext the target controller could
  not decrypt. Offline/reproducible CI pins `--cert`/env instead. (Removed in
  `refactor/drop-cert-cache`; previously a `--refresh-cert` flag bypassed the cache.)
- **Output filename:** `<secret-name>.yaml`, written to the current working directory.
- **Name/namespace validation:** both positional args must be DNS-1123 labels; path-traversal
  / flag-injection inputs are rejected with `InvalidInputError` before any side effect.
- **`edit` source = the local working copy (precedence).** `edit` writes the local
  `<name>.yaml` but reads decrypted values from the cluster, so a non-deployed edit diverges the
  two. To keep read/write consistent and never lose un-deployed work: edit the **local file
  offline** (redacted keep/reseal/remove via `--merge-into`) when it diverges from the deployed
  SealedSecret or the SealedSecret is absent from the cluster; otherwise (no local file, or it
  matches what is deployed) seed from the **cluster** (full decrypted values). After a `--deploy`
  the file matches the cluster again, so full values return. Divergence is detected without
  decryption by comparing `spec.encryptedData`/`template` (`RKSeal::SealedSecret.diverged?`).
  Only a definitive `NotFound` routes offline; an unreachable cluster is surfaced (use `--local`
  to force offline). A cluster-present, non-diverged edit never falls back to a blind merge.
- **`edit` scope preservation:** read from the cluster SealedSecret's scope annotation,
  falling back to the local `<name>.yaml`, then `strict`; `--scope` overrides.
- **`edit` deploy:** never the default — explicit `--deploy` on the current context, with an
  interactive confirmation via `ContextGuard` (`--yes` skips it for pipelines). No in-code
  context allow-list.
- **Integration-test controller install:** raw upstream `controller.yaml` (controller +
  CRD into `kube-system`); already installed on `docker-desktop`, where `kubeseal
  --fetch-cert` works.

No open decisions remain: the Phase 0 questions (buffer round-trip semantics, `--from-file`
vs. editor interaction, empty/unchanged-buffer behaviour, and `type`/`metadata` →
`spec.template` against kubeseal v0.36.6) are all resolved and reflected above.

When writing Ruby here, invoke the `ruby-expert` skill for idiomatic gem/CLI design.
