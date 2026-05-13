# clustergroup_discovery

Ansible role that lists **which clustergroup value stems are in use** for a Validated Patterns checkout, without scanning every `values-*.yaml` on disk.

## Behavior

1. Resolve **`pattern_dir`** the same way as `pattern_settings` (extra var, `PATTERN_DIR`, then `PWD` / `pwd`).
2. Read **`main.clusterGroupName`** from `values-global.yaml` under `pattern_dir` (or use `main_clustergroup` / `main_clustergroupname` if the play already set them).
3. Load **`values-<main>.yaml`** or **`values-<main>.yml`** and read **`clusterGroup.managedClusterGroups`**. For each entry, the managed name is **`value.name`** if set, otherwise the **YAML key** (same convention as the clustergroup chart for managed cluster groups).
4. Expose facts:
   - **`managed_clustergroup_names`** — sorted unique managed names
   - **`clustergroup_load_order`** — `[main, …managed]` (main first; used when merging so later stems override duplicate `applications` keys)
   - **`clustergroup_names`** — sorted list of all stems (main + managed)
   - **`clustergroup_file_entries`** — `{name, path}` only for stems where a local `values-<stem>.yaml|yml` exists

Optional: set **`clustergroup_discovery_parse_documents: true`** to fill **`clustergroup_documents`** (`<stem>` → parsed YAML root) for each file in `clustergroup_file_entries`.

## Playbooks

- `playbooks/list_clustergroups.yml` — runs `pattern_settings` + this role and prints the facts above.
- `playbooks/parse_clustergroup_values.yml` — same with parsing enabled.

Requires `ANSIBLE_ROLES_PATH` (or collection layout) so `pattern_settings` and this role resolve.

## Using this role from other Ansible

Include **`clustergroup_discovery`** (after **`pattern_settings`** or an equivalent that sets **`pattern_dir`** / **`main_clustergroup`**) whenever you need **`clustergroup_load_order`**, **`clustergroup_file_entries`**, or parsed **`clustergroup_documents`** before loading clusterGroup values per stem.
