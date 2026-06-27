# rkseal

Interactively create and edit Kubernetes [SealedSecrets](https://github.com/bitnami-labs/sealed-secrets)
from your terminal, in the spirit of `knife vault create/edit`.

`rkseal` wraps the `kubeseal` CLI. You edit a **full Kubernetes Secret manifest** in
`$EDITOR`; `rkseal` seals it with the controller's public key and writes the resulting
`SealedSecret` to the current directory. The plaintext buffer lives only on a RAM-backed
path and is destroyed when you are done — it never touches persistent disk.

## Commands

```sh
rkseal create    <namespace> <secret-name>   # author a new sealed secret
rkseal edit      <namespace> <secret-name>   # edit an existing one
rkseal reencrypt <namespace> <secret-name>   # rotate to the controller's newest key
rkseal validate  <namespace> <secret-name>   # check a SealedSecret with the controller
rkseal view      <namespace> <secret-name>   # print the live Secret (read-only)
rkseal list      [namespace]                 # list SealedSecrets (metadata only)
rkseal version                               # print the installed rkseal version
```

- `create` opens an empty, commented Secret template for you to fill in.
- `edit` reads the **live** unsealed Secret from the cluster
  (`kubectl get secret … -o json`) — the only way to recover current values — opens it for
  editing, then re-seals. If the Secret is absent from the cluster but a local
  `<secret-name>.yaml` exists (e.g. you ran `create` but never deployed), `rkseal` switches
  **automatically to an offline local edit** (see [`edit --local`](#edit---local-offline)).
  Only if **neither** the cluster Secret nor a local file exists does it fail fast and point
  you at `create`.
- `reencrypt` rotates an existing SealedSecret onto the controller's current sealing key
  (`kubeseal --re-encrypt`) without exposing plaintext. It reads the local
  `<secret-name>.yaml` if present, otherwise the live SealedSecret; if neither exists it
  points you at `create`. The result is written back to `<secret-name>.yaml`.
- `validate` asks the controller whether a SealedSecret is well-formed and decryptable for
  its target (`kubeseal --validate`) — a safe pre-flight check. It validates the local
  `<secret-name>.yaml`, or any file via `--file <path>`. Prints `valid` and exits 0, or
  prints the reason and exits non-zero.
- `view` prints the live unsealed Secret manifest to **STDOUT, read-only** — no editor, no
  RAM workspace, no file written.
- `list` prints a table of the SealedSecret objects in the cluster (columns **NAMESPACE,
  NAME, SCOPE, AGE**). Give a `[namespace]` to scope it to one namespace; omit it to list all.
  **Read-only and metadata-only** — it never prints encrypted data (not even the data keys).
- `create`, `edit`, and `reencrypt` write `<secret-name>.yaml` into the current working
  directory. `edit` and `reencrypt` can deploy with `kubectl apply`, but **only** with an
  explicit opt-in flag, and only after confirming the active kube context.

In the `edit` buffer, `data:` values are shown as **base64, verbatim** — they are never
decoded to plaintext. To change a value readably, add it under a `stringData:` block; on
save it is folded into `data` (and wins per key). The seeded buffer includes a worked
example to make this obvious. Pass `--string-data` to decode the **whole** buffer to plaintext
`stringData` up front (an opt-in plaintext exposure).

### `edit` flags & behaviour

- `--scope strict|namespace-wide|cluster-wide` — by default `edit` **preserves the existing
  scope**: it reads the SealedSecret's scope annotation from the cluster, falling back to the
  local `<secret-name>.yaml`, then to `strict`. Pass `--scope` to override.
- `--deploy` — after writing, `kubectl apply` the result. Surfaces the active kube context
  and asks you to confirm first. Never the default.
- `--yes` — skip the interactive deploy confirmation (only meaningful together with
  `--deploy`), for non-interactive pipelines.
- `--local` — force the offline local edit without contacting the cluster at all (see below).
- `--string-data` — decode the live Secret's `data` into plaintext `stringData` for editing,
  instead of showing it as raw base64.
- `--cert`, `--controller-name`, `--controller-namespace` — control which
  controller certificate is used to re-seal (same as `create`).
- **No-op short-circuit:** if you save the buffer without changing anything, `rkseal` writes
  no file (re-sealing identical input would only produce a spurious ciphertext diff). Because
  nothing new is produced, a `--deploy` on an unchanged secret deploys **nothing**.

#### `edit --local` (offline)

When a SealedSecret was authored with `create` but **never deployed**, there is no unsealed
Secret in the cluster to recover values from. `rkseal` then edits the local
`<secret-name>.yaml` **offline** — reached automatically when the cluster Secret is absent
but the local file exists, or forced with `--local` (which never contacts the cluster, useful
when it is unreachable).

Because a SealedSecret cannot be decrypted, every existing key is shown as `<redacted>`:

- **leave it `<redacted>`** — the existing ciphertext is kept byte-for-byte (no re-seal),
- **replace the value** (or add a new key) — that key is re-sealed and merged in,
- **delete the line** — that key is removed.

Scope is **fixed** in this mode (`--scope` is rejected) and `name`/`namespace` cannot change —
kept ciphertext binds them and cannot be re-sealed without its plaintext. The automatic
fallback fires only on a definitive "not found"; an **unreachable** cluster surfaces as an
error instead (use `--local` to force offline). `--deploy` / `--yes` behave exactly as for the
online `edit`.

### `create` flags

- `--scope`, `--type`, `--cert`, `--controller-name`, `--controller-namespace`.
- `--from-file key=path` (repeatable) — pre-seed a value from a file (binary-safe, stored as
  base64) before the editor opens.
- `--no-edit` — seal the pre-seeded Secret directly, without opening `$EDITOR` (handy for
  TLS / dockerconfig / binary payloads).
- `--string-data` — seed the buffer with a plaintext `stringData` block instead of base64
  `data`, so you type values in clear (folded into `data` on save).
- The controller certificate is resolved up front, so an unreachable controller fails fast
  **before** you start editing.

### `reencrypt` flags

- `--deploy` / `--yes` — same deploy semantics as `edit` (opt-in, context-confirmed; `--yes`
  skips the prompt).
- `--cert`, `--controller-name`, `--controller-namespace`.

### `validate` flags

- `--file <path>` — validate an arbitrary SealedSecret manifest instead of the local
  `<secret-name>.yaml` (then `NAMESPACE`/`NAME` are optional).
- `--cert`, `--controller-name`, `--controller-namespace`.

### `view` flags

- `--reveal` — decode `data` and print values as plaintext `stringData` (default shows raw
  base64, consistent with `edit`). Read-only: `view` never writes a file or opens an editor.

### Controller certificate

`create`, `edit`, `reencrypt`, and `validate` resolve the controller's public cert from, in
order: `--cert <file|URL>`, the `SEALED_SECRETS_CERT` env var (both offline — nothing is
contacted), otherwise a fresh `--fetch-cert` from the live controller. **The cert is never
cached on disk** — it is re-fetched every run, so a seal is always bound to the current kube
context's controller key. For offline or reproducible (GitOps/CI) seals, pin `--cert` or
`SEALED_SECRETS_CERT` to a committed certificate.

## Requirements

- Ruby **4.0.2** (managed with `rvm` + a dedicated `rkseal` gemset).
- `kubeseal` (developed against **v0.36.6**) and `kubectl` on your `PATH`.
- Access to a cluster running the sealed-secrets controller (for `--fetch-cert`, `edit`,
  and deploys).

## Development

```sh
rvm use 4.0.2@rkseal --create   # isolated gemset — never install gems globally
bundle install
bundle exec rspec               # unit suite (adapters stubbed; no cluster needed)
bundle exec rubocop             # lint
bundle exec exe/rkseal create my-namespace my-secret
```

Unit tests stub the `kubeseal` / `kubectl` / `$EDITOR` adapters, so the suite runs without
a cluster. Real cluster operations are reserved for explicit integration tests gated on the
`docker-desktop` context.

## Security model

- **Plaintext never hits persistent disk.** The edit buffer is RAM-backed
  (`tmpfs`/`/dev/shm` on Linux, an ephemeral `hdiutil` RAM disk on macOS) and is shredded
  and torn down on exit, including on error or signal.
- **Deploys confirm the active context.** Applying to the wrong cluster is the dangerous
  operation, so deploy is never the default: `rkseal` surfaces the current kube context and
  asks you to confirm before `kubectl apply`. There is no in-code allow-list — `rkseal` uses
  whatever context is active — so switch context deliberately before deploying (`--yes`
  bypasses only the prompt, not the `--deploy` opt-in).
- **Names are validated at the boundary.** `<namespace>` and `<secret-name>` must be valid
  Kubernetes DNS-1123 names; anything else (path traversal like `../`, a leading `-` that
  could be read as a `kubectl`/`kubeseal` flag, `/`, uppercase, …) is rejected up front,
  before any editor, cluster call, or file write.

## License

MIT — see [LICENSE.txt](LICENSE.txt).
