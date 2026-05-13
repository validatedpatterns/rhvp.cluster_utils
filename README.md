# Ansible Collection - rhvp.cluster_utils

This collection represents the collected Ansible code from the Validated Patterns framework common repository.

The main purpose of this collections are to:

1. Assist with the management of secrets in Validated Patterns clusters, including unsealing Vault, and parsing and
loading local secrets files into VP secrets stores.

2. Help manage imperative and other utility functions of the cluster

## Clustergroup discovery

The **`clustergroup_discovery`** role lists **main and managed clustergroup value stems** for a Validated Patterns checkout (from **`values-global.yaml`** and **`clusterGroup.managedClusterGroups`** in the main **`values-<main>.yaml|yml`**), and which local **`values-<stem>.yaml|yml`** files exist.

- **`playbooks/list_clustergroups.yml`** — prints discovery facts (stems, load order, file paths).
- **`playbooks/parse_clustergroup_values.yml`** — same, plus optional YAML parse into **`clustergroup_documents`**.

See **`roles/clustergroup_discovery/README.md`** for variables and behavior.

## Pattern repository directory (`pattern_dir`)

Playbooks need the path to your pattern Git checkout (where **`values-global.yaml`**
and related files live). Resolution order: extra var **`pattern_dir`**, environment
variable **`PATTERN_DIR`**, then **`PWD`** and **`pwd`**.

When running from the imperative container or another fixed working directory,
pass the repository root explicitly, for example **`-e pattern_dir=/git/repo`** (or add
equivalent extra vars via **`clusterGroup.imperative.extraPlaybookArgs`** in the
clustergroup chart).
