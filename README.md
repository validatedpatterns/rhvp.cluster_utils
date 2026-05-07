# Ansible Collection - rhvp.cluster_utils

This collection represents the collected Ansible code from the Validated Patterns framework common repository.

The main purpose of this collections are to:

1. Assist with the management of secrets in Validated Patterns clusters, including unsealing Vault, and parsing and
loading local secrets files into VP secrets stores.

2. Help manage imperative and other utility functions of the cluster

## SS CSI workload auth notes

`vault_utils` can read `ssCsiWorkloadAuth` entries from clustergroup values and
create Vault Kubernetes auth roles for hub and spoke workloads.

By default it loads **merged** clustergroup YAML from an in-cluster `ConfigMap`
named `values-<main_clustergroupname>` in `openshift-gitops` (override with
`vault_ss_csi_clustergroup_configmap_namespace` and
`vault_ss_csi_clustergroup_configmap_name`). It looks for a data key such as
`values.yaml` unless you set `vault_ss_csi_clustergroup_configmap_key`. The
document must include a top-level `clusterGroup` key. If the `ConfigMap` is
missing or unusable, it falls back to
`pattern_dir/values-<main_clustergroupname>.yaml` when
`vault_ss_csi_fallback_local_clustergroup_file` is true.

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
