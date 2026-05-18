# Ansible Collection - rhvp.cluster_utils

This collection represents the collected Ansible code from the Validated Patterns framework common repository.

The main purpose of this collections are to:

1. Assist with the management of secrets in Validated Patterns clusters, including unsealing Vault, and parsing and
loading local secrets files into VP secrets stores.

2. Help manage imperative and other utility functions of the cluster

## Pattern repository directory (`pattern_dir`)

Playbooks need the path to your pattern Git checkout (where **`values-global.yaml`**
and related files live). Resolution order: extra var **`pattern_dir`**, environment
variable **`PATTERN_DIR`**, then **`PWD`** and **`pwd`**.

When running from the imperative container or another fixed working directory,
pass the repository root explicitly, for example **`-e pattern_dir=/git/repo`** (or add
equivalent extra vars via **`clusterGroup.imperative.extraPlaybookArgs`** in the
clustergroup chart).
