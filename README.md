# Ansible Collection - rhvp.cluster_utils

This collection represents the collected Ansible code from the Validated Patterns framework common repository.

The main purpose of this collections are to:

1. Assist with the management of secrets in Validated Patterns clusters, including unsealing Vault, and parsing and
loading local secrets files into VP secrets stores.

2. Help manage imperative and other utility functions of the cluster

## Secrets loading

The collection distinguishes **primary** values-secret files (the usual pattern secrets) from optional **bootstrap** values-secret files (extra content loaded with the `none` backing store into the cluster, independent of `values-global.yaml` `secretStore.backend`).

### Primary values-secret (standard load)

- **Backing store** comes from `values-global.yaml`: `.global.secretStore.backend` (default `vault`). That drives parsing and whether secrets go to Vault or Kubernetes.
- **Discovery order** when `VALUES_SECRET` is unset (first existing file wins):  
  `~/.config/hybrid-cloud-patterns/values-secret-<pattern>.yaml`,  
  `~/.config/validated-patterns/values-secret-<pattern>.yaml`,  
  `~/values-secret-<pattern>.yaml`,  
  `~/values-secret.yaml`,  
  then `<pattern_dir>/values-secret.yaml.template`.
- When `VALUES_SECRET` is set to an existing path, that file is used for the **primary** load. If bootstrap loading already consumed that same path because it was a bootstrap-named file, the primary pass temporarily ignores `VALUES_SECRET` so the primary search can fall back to the paths above.

Files may be plain YAML or `ansible-vault` encrypted.

### Bootstrap values-secret (optional)

Bootstrap files are **never** read from `<pattern_dir>/` (no `values-secret-*-bootstrap.yaml` under the pattern tree).

Bootstrap files may be **plain YAML or `ansible-vault` encrypted**, the same as primary values-secret files: when encrypted, Ansible prompts for the vault password (or uses your usual `ansible-playbook` vault options).

When not using `VALUES_SECRET` for bootstrap, candidates are checked in order (first existing file wins):

- `~/.config/hybrid-cloud-patterns/values-secret-<pattern>-bootstrap.yaml`
- `~/.config/validated-patterns/values-secret-<pattern>-bootstrap.yaml`
- `~/values-secret-<pattern>-bootstrap.yaml`
- `~/values-secret-bootstrap.yaml`

Alternatively, set `VALUES_SECRET` to an **existing** file whose name ends with `-bootstrap.yaml` (or `-bootstrap.yml`) to use that path for bootstrap discovery in flows that support it.

**Bootstrap is always parsed and applied with backing store `none`** (Kubernetes secret injection path), which requires schema version 2.0 or newer in the bootstrap file.

### Playbooks and flows

- **`playbooks/load_secrets.yml`**  
  Respects `.global.secretLoader.disabled` in `values-global.yaml`. When enabled: `cluster_pre_check`, optional **bootstrap** load (if a bootstrap file exists; **not** an error if missing), then **primary** discovery, parse, and load using the configured backend.

- **`playbooks/load_bootstrap_secrets.yml`**  
  Convenience wrapper: `determine_pattern_dir`, `determine_pattern_name`, then imports `load_secrets.yml` (same combined bootstrap-then-primary behavior as install).

- **`playbooks/load_bootstrap_secrets_only.yml`**  
  **Bootstrap only**: same pattern discovery plays and `pattern_settings`, then only bootstrap inject (with retries). **Fails** if no bootstrap file is found. Does **not** read `secretLoader.disabled` or load the primary file.

- **`playbooks/display_secrets_info.yml`**  
  Loads and displays parsed primary secrets (using the backend from `values-global`). If a bootstrap file exists, also parses and displays it with backing store `none`. Missing bootstrap is not an error.

Typical usage passes the pattern checkout as `pattern_dir` (for example `-e pattern_dir=/path/to/pattern`). If you omit it, the same resolution as `pattern_settings` applies: `PATTERN_DIR`, then `PWD`, then the `pwd` command.

`playbooks/install.yml` imports `load_secrets.yml` after the pattern install playbook, so the combined bootstrap-then-primary flow runs during install when secret loading is enabled.

### Bootstrap retries

Bootstrap **inject** retries (parse plus Kubernetes apply) are controlled on the role defaults / extra-vars:

- `vp_secrets_bootstrap_retry_max` (default `20`)
- `vp_secrets_bootstrap_retry_delay` (seconds between attempts, default `30`)

These apply to the optional bootstrap phase inside `load_secrets` and to `load_bootstrap_secrets_only.yml`.

Per-secret namespace readiness (before each `kubernetes.core.k8s` apply) uses role defaults on `k8s_secret_utils`:

- `k8s_secret_namespace_check_retries` (default `5`) and `k8s_secret_namespace_check_delay` (seconds between attempts, default `45`).

If the namespace still does not exist after those attempts, the inject fails and the **outer** bootstrap retry re-runs parse plus all secret injections from the start.

### Roles (implementation notes)

- `roles/load_secrets/tasks/main.yml` implements the **combined** flow (optional bootstrap, then primary).
- `roles/load_secrets/tasks/bootstrap_only.yml` is used only when you invoke the `load_secrets` role with `tasks_from: bootstrap_only.yml` (as `load_bootstrap_secrets_only.yml` does).
- `roles/find_vp_secrets` resolves primary files (`tasks/main.yml`) and optional bootstrap discovery (`tasks/find_optional_bootstrap.yml`).
