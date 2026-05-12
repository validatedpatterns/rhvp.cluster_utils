# Ansible Collection - rhvp.cluster_utils

This collection represents the collected Ansible code from the Validated Patterns framework common repository.

The main purpose of this collections are to:

1. Assist with the management of secrets in Validated Patterns clusters, including unsealing Vault, and parsing and
loading local secrets files into VP secrets stores.

2. Help manage imperative and other utility functions of the cluster

## Secrets loading

Secrets are loaded from a **single primary** values-secret file (plus optional `values-secret.yaml.template` under the
pattern tree as a last-resort discovery path). There are **no** separate `*-bootstrap.yaml` files or `VALUES_SECRET_BOOTSTRAP`
paths; early cluster bootstrap uses **per-entry** `bootstrap` fields on v2 secrets in that same primary file.

### Primary values-secret

- **Backing store** comes from `values-global.yaml`: `.global.secretStore.backend` (default `vault`). That drives parsing
  and whether secrets go to Vault or Kubernetes.
- **Discovery order** when `VALUES_SECRET` is unset (first existing file wins):  
  `~/.config/hybrid-cloud-patterns/values-secret-<pattern>.yaml`,  
  `~/.config/validated-patterns/values-secret-<pattern>.yaml`,  
  `~/values-secret-<pattern>.yaml`,  
  `~/values-secret.yaml`,  
  then `<pattern_dir>/values-secret.yaml.template`.
- When `VALUES_SECRET` is set to an existing path, that file is used for the primary load.

Files may be plain YAML or `ansible-vault` encrypted.

### Per-secret `bootstrap` in v2 primary files

On schema **2.0** primary values-secret files, each secret may set `bootstrap`:

- **`bootstrap: true`** (or string equivalents such as `yes`, `both`) — the secret is included in the **early**
  Kubernetes inject pass (`none` backend) and is **also** parsed in the **primary** pass into the configured backend
  (Vault or Kubernetes as in `values-global.yaml`). It must not use `onMissingValue: generate` on any field (the early
  pass cannot generate in Vault).
- **`bootstrap: only`** (or `early`) — the secret is **only** in the early inject pass; the primary pass **omits** it.
- **Unset / false** — normal primary-only secret.

Invalid `bootstrap` scalars fail parsing with a clear error.

Early inject runs **before** the primary backend load: during `playbooks/install.yml`, immediately after the
pattern-install manifests are applied (`operator_deploy.yml`), then again inside `load_secrets` unless that early pass
already completed (duplicate inject is skipped).

### Playbooks and flows

- **`playbooks/load_secrets.yml`**  
  Respects `.global.secretLoader.disabled` in `values-global.yaml`. When enabled: `cluster_pre_check`, primary file
  discovery, early Kubernetes inject for bootstrap-tagged v2 entries (when present), then parse and load the rest into
  the configured backend.

- **`playbooks/load_bootstrap_secrets.yml`**  
  Convenience wrapper: `determine_pattern_dir`, `determine_pattern_name`, then imports `load_secrets.yml` (same behavior
  as install).

- **`playbooks/load_bootstrap_secrets_only.yml`**  
  **Early bootstrap inject only**: same pattern discovery plays and `pattern_settings`, then only the Kubernetes inject
  for bootstrap-tagged secrets in the primary file (with retries). **Fails** if no primary file exists or there are no
  bootstrap-tagged v2 entries. Does **not** read `secretLoader.disabled` or load into Vault / primary backend.

- **`playbooks/display_secrets_info.yml`**  
  Loads and displays parsed secrets (using the backend from `values-global`). For v2 files with any bootstrap-tagged
  entries, output is split into **`early_bootstrap_inject`** (none backend, early K8s view; includes `bootstrap: true`
  and `bootstrap: only`) and **`primary_backend`** (configured backend; includes normal secrets and **`bootstrap: true`**
  again so dual-mode entries appear in both groups). Otherwise a single parse is shown as before.

Typical usage passes the pattern checkout as `pattern_dir` (for example `-e pattern_dir=/path/to/pattern`). If you omit
it, the same resolution as `pattern_settings` applies: `PATTERN_DIR`, then `PWD`, then the `pwd` command.

`playbooks/install.yml` imports `load_secrets.yml` after the pattern install playbook. When secret loading is enabled,
early bootstrap inject from the primary file runs at the end of `operator_deploy.yml` (right after apply), then
`load_secrets.yml` continues without repeating that inject when it already succeeded.

### Early bootstrap inject retries

Outer retries (parse plus Kubernetes apply) are controlled on the role defaults / extra-vars:

- `vp_secrets_bootstrap_retry_max` (default `20`)
- `vp_secrets_bootstrap_retry_delay` (seconds between attempts, default `30`)

These apply to the early inject path inside `load_secrets` and to `load_bootstrap_secrets_only.yml`.

Per-secret namespace readiness (before each `kubernetes.core.k8s` apply) uses role defaults on `k8s_secret_utils`:

- `k8s_secret_namespace_check_retries` (default `5`) and `k8s_secret_namespace_check_delay` (seconds between attempts, default `45`).

If the namespace still does not exist after those attempts, the inject fails and the **outer** retry re-runs parse plus
all secret injections from the start.

### Roles (implementation notes)

- `roles/load_secrets/tasks/main.yml` implements the **combined** flow (early inject from primary file, then primary
  backend load).
- `roles/load_secrets/tasks/bootstrap_only.yml` is used only when you invoke the `load_secrets` role with
  `tasks_from: bootstrap_only.yml` (as `load_bootstrap_secrets_only.yml` does).
- `roles/find_vp_secrets` resolves the primary file (`tasks/main.yml`).
- v2 parsing and phase filters (`bootstrap_only`, `exclude_bootstrap`, `all`) are implemented in
  `plugins/module_utils/parse_secrets_v2.py` (single `bootstrap` normalizer: off / dual / early-only).
