# Ansible Collection - rhvp.cluster_utils

This collection represents the collected Ansible code from the Validated Patterns framework common repository.

The main purpose of this collections are to:

1. Assist with the management of secrets in Validated Patterns clusters, including unsealing Vault, and parsing and
loading local secrets files into VP secrets stores.

2. Help manage imperative and other utility functions of the cluster

## SS CSI workload auth notes

`vault_utils` can read `ssCsiWorkloadAuth` entries from clustergroup values and
create Vault Kubernetes auth roles for hub and spoke workloads.

At the application level (`clusterGroup.applications.<app>`), the relevant
inputs are:

- `ssCsiWorkloadAuth` (list)
- `ssCsiWorkloadAuth[].serviceAccount` (required)
- `ssCsiWorkloadAuth[].namespace` (optional)
- `ssCsiWorkloadAuth[].cluster` (optional)
- `ssCsiWorkloadAuth[].roleSlug` / `role_slug` (optional)
- application `namespace` (optional default for entry namespace)

CA material management for SS CSI is not handled in this collection anymore.
Provide CA distribution using a separate chart or platform mechanism.

For the complete flow and task ordering, see
`secrets-initialization-and-vault-unseal.md`.
