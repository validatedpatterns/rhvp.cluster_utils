# Secrets initialization process (cluster_utils)

This document describes how Vault and application secrets are bootstrapped when you run the **vault** playbook and the **`vault_utils`** role, with emphasis on **`vault_unseal`** (`roles/vault_utils/tasks/vault_unseal.yaml`).

## Entry point

- **Playbook:** `playbooks/vault.yml`
- **Hosts:** `localhost`, `connection: local`, `gather_facts: false`
- **Roles (order):**
  1. **`pattern_settings`** — Resolves `pattern_dir` (extra var, `PATTERN_DIR`,
     then `PWD` / `pwd`) and loads `values-global.yaml` (including
     `main.clusterGroupName` as `main_clustergroup`). When `pattern_settings` is
     not in the play, **`vault_ss_csi_workload_auth`** repeats the same
     `pattern_dir` resolution and, if needed, reads `values-global.yaml` under
     that directory to set `main_clustergroup` / `main_clustergroupname` before
     loading merged clustergroup values.
  2. **`find_vp_secrets`** — Locates pattern secrets inputs as used elsewhere in the repository.
  3. **`cluster_pre_check`** — Verifies Python `kubernetes` import, kubeconfig (`KUBECONFIG` or `~/.kube/config`), or in-cluster operation via `KUBERNETES_SERVICE_HOST`.
  4. **`vault_utils`** — Performs Vault init, unseal, backends/policies, spokes, and pushing secrets from `values-secret` files.

## `vault_utils` role task order (`roles/vault_utils/tasks/main.yml`)

Tasks run in this fixed order (each block has an Ansible **tag** of the same name for selective runs):

| Order | Import | Tag |
| ----- | ------ | --- |
| 1 | `vault_init.yaml` | `vault_init` |
| 2 | `vault_unseal.yaml` | `vault_unseal` |
| 3 | `vault_secrets_init.yaml` | `vault_secrets_init` |
| 4 | `vault_spokes_init.yaml` | `vault_spokes_init` |
| 5 | `push_secrets.yaml` | `push_secrets` |
| 6 | `vault_jwt.yaml` | `vault_jwt` (only if `vault_jwt_config` is true) |

---

## Step 1: `vault_init` (`vault_init.yaml`)

Purpose: **first-time Vault operator initialization** if the cluster's Vault is not already initialized.

1. **Include `vault_status.yaml`** (see below) so `vault_status` is populated.
2. **Set `vault_initialized`** from `vault_status['initialized']`.
3. **If not initialized:** run `vault operator init -format=json` inside pod `{{ vault_pod }}` in namespace `{{ vault_ns }}` (retries: 10, delay 15s) to tolerate startup 500s.
4. **If not initialized:** parse stdout as JSON into `vault_init_json`.
5. **If not initialized:** create/update Kubernetes **Secret** `{{ unseal_secret }}` in `{{ unseal_namespace }}` with key `vault_data_json` (base64-encoded JSON of the init output, including **root token** and **unseal keys**).

**Defaults (from `roles/vault_utils/defaults/main.yml`):** `unseal_secret: vaultkeys`, `unseal_namespace: imperative`.

**Note:** A comment in the task file mentions `unseal_from_cluster`; the **actual** `when` clause only requires `not vault_initialized` — the secret is saved whenever init runs successfully.

If Vault is **already** initialized, all mutating steps are skipped.

---

## Step 2: `vault_unseal` (`vault_unseal.yaml`) — detailed

Purpose: **unseal** the leader (and followers in HA), **join Raft** followers to the leader, and **log in** with the root token so subsequent tasks in the same play can use Vault. Most steps run **only when `vault_sealed` is true** (Vault reported sealed in status).

### 2.1 Shared prerequisite: `vault_status.yaml` (included first)

This file is **not** tagged separately; it runs as part of both `vault_init` and `vault_unseal` (and again inside `push_secrets`).

1. **Wait for namespace** `{{ vault_ns }}` to exist (`k8s_info` Namespace, retries 20 × 45s).
2. **Wait for pod** `{{ vault_pod }}` in that namespace (retries 20 × 45s).
3. **Exec** `vault status -format=json` on the leader pod until the result includes `'rc'` (handles transient 500 / handshake issues; retries 20 × 45s).
4. **Set fact `vault_status`** from parsed JSON stdout.
5. **List pods** in `{{ vault_ns }}` with label `component=server`, build **`vault_pods`** (names).
6. **Set `followers`** = all server pods **except** `{{ vault_pod }}` (the leader name from defaults is `vault-0`).

### 2.2 `vault_unseal` proper

1. **Include `vault_status.yaml`** again (refreshes `vault_status`, `followers`, etc.).
2. **Set `vault_sealed`** = `vault_status['sealed']` (boolean).
3. **If sealed:** read Secret **`{{ unseal_namespace }}/{{ unseal_secret }}`** (`k8s_info`); register `vault_init_data`.
4. **If sealed:** set **`vaultkeys_exists`** from whether the secret has any resources.
5. **If sealed and the secret is missing:** **`meta: end_play`** — the play stops. Unseal cannot proceed without the init material stored in the cluster.
6. **If sealed:** decode `vault_data_json` from the secret, parse JSON → **`vault_init_json`**.
7. **If sealed:** set **`root_token`** and **`unseal_keys`** from `vault_init_json` (`root_token`, `unseal_keys_hex`).
8. **If sealed — Unseal leader:** for **each** key in `unseal_keys`, exec on the leader pod: `vault operator unseal "<key>"`.
9. **If sealed and `followers` is non-empty — Join Raft:** for each follower pod, exec:  
   `vault operator raft join http://{{ vault_pod }}.{{ vault_ns }}-internal:8200`  
   (retries 10, delay 15s per follower).
10. **If sealed and followers exist — Unseal followers:** nested loop over `followers x unseal_keys` (each follower gets every unseal key applied via `vault operator unseal` on that follower's pod).
11. **If sealed — Login:** on the leader pod: `vault login "{{ root_token }}"`.

**If Vault is already unsealed** (`vault_sealed` false): steps 3–11 are skipped (no secret read, no unseal, no join, no login from this file). The play continues to `vault_secrets_init`.

#### Operational implications

- **HA:** Followers are discovered by label `component=server`; leader is fixed by name `vault_pod` (default `vault-0`).
- **Security:** Root token and unseal keys live in the **`vaultkeys`** secret in **`imperative`** (by default); anyone with cluster access to that secret can unseal and administer Vault.
- **Cold start:** Run **`vault_init`** before **`vault_unseal`** in the same play (as `main.yml` does), or ensure the `vaultkeys` secret already exists if Vault was initialized out-of-band.

---

## Step 3: `vault_secrets_init` (`vault_secrets_init.yaml`)

Runs **after** unseal. Configures Vault **engines**, **Kubernetes auth** for External Secrets Operator, **policies**, and the **hub Kubernetes role**; then includes SS CSI workload auth tasks.

Summary:

1. Enable **KV v2** secrets engine at `{{ vault_base_path }}` (default `secret`) if not already present.
2. Enable **`kubernetes`** auth at path `{{ vault_hub }}` (default `hub`) if missing.
3. Resolve **External Secrets** SA token: prefer Secret `{{ external_secrets_ns }}/{{ external_secrets_secret }}` (defaults: `external-secrets` / `ocp-external-secrets`); else legacy `golang-external-secrets` / `golang-external-secrets`. Fail if neither exists.
4. **`vault write auth/{{ vault_hub }}/config`** with `token_reviewer_jwt`, `kubernetes_host`, CA from the Vault pod's service account, issuer `https://kubernetes.default.svc`.
5. Write **HCL policy files** in the pod under `/tmp` and **`vault policy write`** for: global, pushsecrets (data + metadata paths), hub path.
6. Read existing **`auth/{{ vault_hub }}/role/{{ vault_hub }}-role`**, merge policies with `vault_hub_role_default_policies`, and **`vault write`** the role when an update is needed (bound SA/namespace from active external-secrets config, TTL from `vault_hub_ttl`).
7. **`include_tasks: vault_ss_csi_workload_auth.yaml`** for optional SS CSI Kubernetes auth roles from pattern values.

### SS CSI: parsing, extraction, and projection

SS CSI workload auth runs from **`include_tasks: vault_ss_csi_workload_auth.yaml`**
(inside **`vault_secrets_init.yaml`**). The pipeline is:

1. **Parsing** — **`vault_ss_csi_load_clustergroup_values.yaml`** chooses merged
   multi-stem loading (**`vault_ss_csi_aggregate_clustergroup_sources`**, default
   true) or **legacy** single-document loading. Merged mode runs
   **`clustergroup_discovery`** then, for each stem in **`clustergroup_load_order`**,
   loads **`ConfigMap` `values-<stem>`** (then optional **`values-<stem>.yaml|yml`**
   under **`pattern_dir`**) and merges **`clusterGroup.applications`** and
   **`clusterGroup.managedClusterGroups`**. See **`roles/vault_utils/README.md`**
   (SS CSI) for variables and task filenames.
2. **Extraction** — Builds per-stem **`_vault_ss_csi_apps_by_stem`** and collects
   **`ssCsiWorkloadAuth`** from **`clusterGroup.applications`** per stem (main stem
   defaults **`cluster`** to **hub**; managed stems default to the **stem name**)
   and from merged **`clusterGroup.managedClusterGroups.*.applications`**.
3. **Projection** — Hub-classified rows get **`vault_ss_csi_apply_one_hub_sscsi_role`**;
   spoke rows are normalized to **`vault_path`** during **`vault_spokes_init`**
   (**`vault_ss_csi_normalize_spoke_entries_to_vault_path`**) and written with
   **`vault_ss_csi_apply_one_spoke_sscsi_role`**.

**Defaults:** ConfigMaps live in **`openshift-gitops`** unless
**`vault_ss_csi_clustergroup_configmap_namespace`** is changed; YAML is read from
data keys in **`vault_ss_csi_clustergroup_configmap_key_candidates`** unless
**`vault_ss_csi_clustergroup_configmap_key`** is set. Each document must define
**`clusterGroup`**. Set **`vault_ss_csi_clustergroup_values_from_configmap`** to
false to force file-only reads. When **`vault_ss_csi_fallback_local_clustergroup_file`**
is true, missing or unusable cluster data falls back to local files as implemented
in **`vault_ss_csi_load_one_clustergroup_values_fragment.yaml`** / legacy tasks.

**Spoke cluster ID and charts:** Before applying SS CSI roles on spokes,
`**vault_ss_csi_normalize_spoke_entries_to_vault_path.yaml`** rewrites each spoke row so **`cluster` equals `vault_path`**
(spoke FQDN) for every cluster that has External Secrets token data (`esoToken`).
That matches Vault Kubernetes auth mounts and ESO.
Pattern charts that render **`SecretProviderClass`** via **vp-sscsi-spc** should keep **`global.clusterDomain`** set to that same FQDN on the spoke; the library builds **`spec.parameters.roleName`** as **`<vaultKubernetesMountPath>-sscsi-<roleSlug>`**, using the mount path (not the short `ssCsiWorkloadAuth.cluster` label).

**Local inspection:** **`playbooks/list_clustergroups.yml`** and
**`playbooks/parse_clustergroup_values.yml`** exercise the **`clustergroup_discovery`**
role; see **`roles/clustergroup_discovery/README.md`**.
`**vault_ss_csi_normalize_spoke_entries_to_vault_path.yaml`** rewrites each spoke row so **`cluster` equals `vault_path`**
(spoke FQDN) for every cluster that has External Secrets token data (`esoToken`).
That matches Vault Kubernetes auth mounts and ESO.
Pattern charts that render **`SecretProviderClass`** via **vp-sscsi-spc** should keep **`global.clusterDomain`** set to that same FQDN on the spoke; the library builds **`spec.parameters.roleName`** as **`<vaultKubernetesMountPath>-sscsi-<roleSlug>`**, using the mount path (not the short `ssCsiWorkloadAuth.cluster` label).

### Vault route CA for SS CSI TLS

The **SS CSI** path in this collection no longer gathers hub ingress CA material or applies CA `ConfigMap` objects.
CA distribution for the Vault route is now expected to be handled by a separate chart.

When using **Secrets Store CSI** against Vault over HTTPS (`vaultSkipTLSVerify: "false"`), ensure your platform/chart layer provides the CA bundle and mount path expected by your SS CSI deployment.
The `vault_utils` role now only configures Vault auth backends, policies, and SS CSI Kubernetes auth roles.

---

## Step 4: `vault_spokes_init` (`vault_spokes_init.yaml`)

Configures Vault for **ACM managed clusters** (Kubernetes auth mounts and roles per spoke, paths under `secret/<fqdn>`, etc.).

**Important:** If there are **no** `ManagedCluster` resources, the ACM API call **failed**, or **`api_found`** is false, the role runs **`meta: end_play`**, which **stops the entire play** immediately.
In that situation **`push_secrets`** and **`vault_jwt`** do **not** run in the same invocation.
For hub-only workflows, use **`--skip-tags vault_spokes_init`** (or run `push_secrets` in a separate tagged run) so secret loading still executes.

---

## Step 5: `push_secrets` (`push_secrets.yaml`)

Purpose: Load **pattern** secrets from disk into Vault using the **`vault_load_secrets`** module.

1. **Include `vault_status.yaml`**.
2. **Retry loop** on leader: `vault status -format=json` until **`sealed` is false** (handles race with async unseal or external unseal).
3. **Retry** until `vault list auth/{{ vault_hub }}/role` shows **`{{ vault_hub }}-role`** (hub role from secrets init).
4. Resolve **`found_file`**: `VALUES_SECRET` env if set and file exists; else `first_found` among pattern-specific paths under `~/.config/...`, `~/values-secret-*.yaml`, `~/values-secret.yaml`, or `{{ pattern_dir }}/values-secret.yaml.template`.
5. Detect **ansible-vault** encryption (first line `$ANSIBLE_VAULT`); if encrypted, **pause** for password and **`ansible-vault view`** to plaintext.
6. **`vault_load_secrets`** with either file path or plaintext, `check_missing_secrets: false`, and `values_secret_template` pointing at `{{ pattern_dir }}/values-secret.yaml.template`.

---

## Step 6: `vault_jwt` (`vault_jwt.yaml`)

Included from `main.yml` only when **`vault_jwt_config | default(false) | bool`** is true. Configures JWT auth and roles as defined in role defaults/vars.

---

## Key variables (defaults)

| Variable | Default | Meaning |
| -------- | ------- | ------- |
| `vault_ns` | `vault` | Vault namespace |
| `vault_pod` | `vault-0` | Leader pod name |
| `vault_hub` | `hub` | Kubernetes auth mount path segment |
| `vault_base_path` | `secret` | KV v2 mount path |
| `unseal_secret` | `vaultkeys` | Secret name holding init JSON |
| `unseal_namespace` | `imperative` | Namespace for unseal secret |

Override via inventory, extra vars, or role vars as needed.

---

## Selective execution (tags)

You can run subsets, for example:

```bash
ansible-playbook playbooks/vault.yml --tags vault_init,vault_unseal
```

Useful for reproducing only init+unseal without spokes or secret push.

---

## Related documentation in repository

- **`roles/vault_utils/README.md`** — Role variables, values-secret v1/v2 formats, Vault path layout (`secret/global`, `secret/hub`, spokes, `secret/pushsecrets`), and the SS CSI **parsing / extraction / projection** section.
- **`roles/clustergroup_discovery/README.md`** — How main + managed clustergroup stems are derived and how **`playbooks/list_clustergroups.yml`** / **`playbooks/parse_clustergroup_values.yml`** use them.
- **`playbooks/process_secrets.yml`** / **`roles/load_secrets`** — Broader "load secrets" flow for patterns (not identical to `vault.yml`, but shares concepts like `find_vp_secrets` and backing store).

---

*Generated from repository `rhvp.cluster_utils` (Ansible tasks as of documentation date). Task files are authoritative if they diverge from this text.*
