# Ansible Collection - rhvp.cluster_utils

This collection represents the collected Ansible code from the Validated Patterns framework common repository.

The main purpose of this collections are to:

1. Assist with the management of secrets in Validated Patterns clusters, including unsealing Vault, and parsing and
loading local secrets files into VP secrets stores.

2. Help manage imperative and other utility functions of the cluster

## SS CSI workload auth notes

`vault_utils` can read `ssCsiWorkloadAuth` entries from clustergroup values and
create Vault Kubernetes auth roles for hub and spoke workloads.

### Parsing (load YAML)

With **`vault_ss_csi_aggregate_clustergroup_sources`** true (default), SS CSI
uses the **`clustergroup_discovery`** role to determine stems: **main** from
`values-global.yaml`, then **managed** names from `clusterGroup.managedClusterGroups`
in the main `values-<main>.yaml|yml`. For **each** stem it loads a document from
the in-cluster **`ConfigMap` `values-<stem>`** (namespace
`openshift-gitops` by default), then falls back to **`pattern_dir/values-<stem>.yaml|yml`**
when enabled. ConfigMap data keys follow **`vault_ss_csi_clustergroup_configmap_key`**
and **`vault_ss_csi_clustergroup_configmap_key_candidates`**. Each document must
include **`clusterGroup`**. Stems are merged in **`clustergroup_load_order`**
(main first, then managed stems sorted) so later sources override duplicate
`clusterGroup.applications` keys. Set **`vault_ss_csi_aggregate_clustergroup_sources`**
to false to load only the **main** document (legacy: single ConfigMap or
`values-<main>.yaml`).

### Extraction (find `ssCsiWorkloadAuth`)

The role builds **`_vault_ss_csi_apps_by_stem`** (per-stem `clusterGroup.applications`)
and a merged **`clusterGroup.managedClusterGroups`**. It collects:

- **`clusterGroup.applications.*.ssCsiWorkloadAuth`** — per stem; the **main**
  stem defaults `cluster` to **hub**; **managed** stems default `cluster` to
  that **stem name** so entries declared only under `values-<managed>.yaml` are
  not misclassified as hub.
- **`clusterGroup.managedClusterGroups.*.applications.*.ssCsiWorkloadAuth`** —
  from the merged map (includes definitions that exist only on managed files).

### Projection (Vault roles)

Rows are appended to **`_ss_csi_all_entries`**, split into hub vs spoke using
the resolved **`cluster`** field, then **hub** identities get Vault Kubernetes
auth roles via **`vault_ss_csi_apply_one_hub_sscsi_role.yaml`**. Spoke rows are
normalized to **`vault_path`** later in the play (**`vault_ss_csi_normalize_spoke_entries_to_vault_path.yaml`**
during **`vault_spokes_init`**) and roles are written on each spoke mount
(**`vault_ss_csi_apply_one_spoke_sscsi_role.yaml`**). Role names use
**`<mount>-sscsi-<slug>`**; slugs come from **`vault_ss_csi_compute_role_slug.yaml`**.

To **inspect** stems and files locally, run **`playbooks/list_clustergroups.yml`**
or **`playbooks/parse_clustergroup_values.yml`** (see **`roles/clustergroup_discovery/README.md`**).

At the application level (`clusterGroup.applications.<app>`), the relevant
inputs are:

- `ssCsiWorkloadAuth` (list)
- `ssCsiWorkloadAuth[].serviceAccount` (required)
- `ssCsiWorkloadAuth[].namespace` (optional)
- `ssCsiWorkloadAuth[].cluster` (optional): matching hint for **which** spoke a
  row applies to (managed cluster group name, `ManagedCluster` name, spoke FQDN
  / `vault_path`, or `clusterGroup` label). For Vault writes, spokes are
  normalized to **`vault_path`** (full DNS), same as External Secrets.
- `ssCsiWorkloadAuth[].roleSlug` / `role_slug` (optional): suffix only; Vault
  role is **`<mount>-sscsi-<slug>`** where **`<mount>`** is hub **`hub`** (or
  configured hub path) or the spoke **`vault_path`**. When using the
  **vp-sscsi-spc** chart, `spec.parameters.roleName` uses the same **mount**
  as `vaultKubernetesMountPath` (typically **`global.clusterDomain`** on
  spokes), not the short `cluster` value.
- application `namespace` (optional default for entry namespace)

CA material management for SS CSI is not handled in this collection anymore.
Provide CA distribution using a separate chart or platform mechanism.

For the complete flow and task ordering, see
`secrets-initialization-and-vault-unseal.md`.

## Pattern repository directory (`pattern_dir`)

Playbooks need the path to your pattern Git checkout (where `values-global.yaml`
and related files live). Resolution order: extra var `pattern_dir`, environment
variable `PATTERN_DIR`, then `PWD` and `pwd`.

When running from the imperative container or another fixed working directory,
pass the repository root explicitly, for example `-e pattern_dir=/git/repo` (or add
equivalent extra vars via `clusterGroup.imperative.extraPlaybookArgs` in the
clustergroup chart).
