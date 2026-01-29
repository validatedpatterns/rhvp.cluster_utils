# Copyright 2022, 2023 Red Hat, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""
Module that implements V2 of the values-secret.yaml spec
"""
from __future__ import absolute_import, division, print_function

__metaclass__ = type

import base64
import os

from ansible_collections.rhvp.cluster_utils.plugins.module_utils.load_secrets_common import (
    SecretsV2Base,
    find_dupes,
    get_ini_value,
    get_version,
    stringify_dict,
)

secret_store_namespace = "validated-patterns-secrets"


class ParseSecretsV2(SecretsV2Base):

    def __init__(self, module, syaml, secrets_backing_store):
        super().__init__(module, syaml)
        self.secrets_backing_store = str(secrets_backing_store)
        self.secret_store_namespace = None
        self.parsed_secrets = {}
        self.kubernetes_secret_objects = []
        self.vault_policies = {}

    def _get_backingstore(self):
        """
        Backing store is now influenced by the caller more than the file. Setting
        Return the backingStore: of the parsed yaml object. In most cases the file
        key was not set anyway - since vault was the only supported option. Since
        we are introducing new options now, this method of defining behavior is
        deprecated, but if the file key is included it must match the option defined
        by values-global in the pattern, or there is an error. The default remains
        'vault' if the key is unspecified.

        Returns:
            ret(str): The value of the top-level 'backingStore:' key
        """
        file_backing_store = str(self.syaml.get("backingStore", "unset"))

        if file_backing_store == "unset":
            pass
        else:
            if file_backing_store != self.secrets_backing_store:
                self.module.fail_json(
                    f"Secrets file specifies '{file_backing_store}' backend but pattern config "
                    f"specifies '{self.secrets_backing_store}'."
                )

        return self.secrets_backing_store

    def _get_vault_policies(self, enable_default_vp_policies=True):
        # Override base class to add YAML sanitization for policies
        policies = super()._get_vault_policies(enable_default_vp_policies)

        # This is useful for embedded newlines, which occur with YAML
        # flow-type scalars (|, |- for example)
        for name, policy in self.syaml.get("vaultPolicies", {}).items():
            policies[name] = self._sanitize_yaml_value(policy)

        return policies

    def _get_secrets(self):
        secrets = self.syaml.get("secrets", [])
        # We check for "None" here because the yaml file is currently
        # filtered thru' from_yaml in module
        # We also check for None here to cover when there is no jinja filter is used (unit tests)
        return [] if secrets == "None" or secrets is None else secrets

    def _get_field_annotations(self, f):
        return f.get("annotations", {})

    def _get_field_labels(self, f):
        return f.get("labels", {})

    def _get_field_kind(self, f):
        # Override the base class implementation to include field name in error message
        found = []
        for i in ["value", "path", "ini_file"]:
            if i in f:
                found.append(i)

        if len(found) > 1:  # you can only have one of value, path and ini_file
            self.module.fail_json(
                f"Both '{found[0]}' and '{found[1]}' cannot be used "
                f"in field {f['name']}"
            )

        if len(found) == 0:
            return ""
        return found[0]

    def _get_secret_store_namespace(self):
        return str(self.syaml.get("secretStoreNamespace", secret_store_namespace))

    def _get_vault_prefixes(self, s):
        return list(s.get("vaultPrefixes", ["hub"]))

    def _get_default_labels(self):
        return self.syaml.get("defaultLabels", {})

    def _get_default_annotations(self):
        return self.syaml.get("defaultAnnotations", {})

    def _append_kubernetes_secret(self, secret_obj):
        self.kubernetes_secret_objects.append(secret_obj)

    def _sanitize_yaml_value(self, value):
        # This is useful for embedded newlines, which occur with YAML
        # flow-type scalars (|, |- for example)
        if value is not None:
            sanitized_value = bytes(value, "utf-8").decode("unicode_escape")
        else:
            sanitized_value = None

        return sanitized_value

    def _create_k8s_secret(self, sname, secret_type, namespace, labels, annotations):
        return {
            "type": secret_type,
            "kind": "Secret",
            "apiVersion": "v1",
            "metadata": {
                "name": sname,
                "namespace": namespace,
                "annotations": annotations,
                "labels": labels,
            },
            "stringData": {},
        }

    # This does what inject_secrets used to (mostly)
    def parse(self):
        self.sanitize_values()
        self.vault_policies = self._get_vault_policies()
        self.secret_store_namespace = self._get_secret_store_namespace()
        backing_store = self._get_backingstore()
        secrets = self._get_secrets()

        total_secrets = 0  # Counter for all the secrets uploaded

        if len(secrets) == 0:
            self.module.warn("No secrets were parsed")
            return total_secrets

        for s in secrets:
            total_secrets += 1
            counter = 0  # This counter is to use kv put on first secret and kv patch on latter
            sname = s.get("name")
            fields = s.get("fields", [])
            vault_prefixes = self._get_vault_prefixes(s)
            secret_type = s.get("type", "Opaque")
            vault_mount = s.get("vaultMount", "secret")
            target_namespaces = s.get("targetNamespaces", [])
            labels = stringify_dict(s.get("labels", self._get_default_labels()))
            annotations = stringify_dict(
                s.get("annotations", self._get_default_annotations())
            )

            self.parsed_secrets[sname] = {
                "name": sname,
                "fields": {},
                "vault_mount": vault_mount,
                "vault_policies": {},
                "vault_prefixes": vault_prefixes,
                "override": [],
                "generate": [],
                "paths": {},
                "base64": [],
                "ini_file": {},
                "type": secret_type,
                "target_namespaces": target_namespaces,
                "labels": labels,
                "annotations": annotations,
            }

            for i in fields:
                self._inject_field(sname, i)
                counter += 1

            if backing_store == "kubernetes":
                k8s_namespaces = [self._get_secret_store_namespace()]
            else:
                k8s_namespaces = target_namespaces

            for tns in k8s_namespaces:
                k8s_secret = self._create_k8s_secret(
                    sname, secret_type, tns, labels, annotations
                )
                k8s_secret["stringData"] = self.parsed_secrets[sname]["fields"]
                self.kubernetes_secret_objects.append(k8s_secret)

        return total_secrets

    def _validate_secrets(self):
        backing_store = self._get_backingstore()
        secrets = self._get_secrets()
        if len(secrets) == 0:
            self.module.warn("No secrets found")
            return (True, "")

        names = []
        for s in secrets:
            # These fields are mandatory
            for i in ["name"]:
                try:
                    unused = s[i]
                except KeyError:
                    return (False, f"Secret {s['name']} is missing {i}")
            names.append(s["name"])

            vault_prefixes = s.get("vaultPrefixes", ["hub"])
            # This checks for the case when vaultPrefixes: is specified but empty
            if vault_prefixes is None or len(vault_prefixes) == 0:
                return (False, f"Secret {s['name']} has empty vaultPrefixes")

            namespaces = s.get("targetNamespaces", [])
            if not isinstance(namespaces, list):
                return (False, f"Secret {s['name']} targetNamespaces must be a list")

            if backing_store == "none" and namespaces == []:
                return (
                    False,
                    f"Secret {s['name']} targetNamespaces cannot be empty for secrets backend {backing_store}",
                )  # noqa: E501

            labels = s.get("labels", {})
            if not isinstance(labels, dict):
                return (False, f"Secret {s['name']} labels must be a dictionary")

            annotations = s.get("annotations", {})
            if not isinstance(annotations, dict):
                return (False, f"Secret {s['name']} annotations must be a dictionary")

            fields = s.get("fields", [])
            if len(fields) == 0:
                return (False, f"Secret {s['name']} does not have any fields")

            field_names = []
            for i in fields:
                (ret, msg) = self._validate_field(i)
                if not ret:
                    return (False, msg)
                field_names.append(i["name"])
            field_dupes = find_dupes(field_names)
            if len(field_dupes) > 0:
                return (False, f"You cannot have duplicate field names: {field_dupes}")

        dupes = find_dupes(names)
        if len(dupes) > 0:
            return (False, f"You cannot have duplicate secret names: {dupes}")
        return (True, "")

    def sanitize_values(self):
        """
        Sanitizes the secrets YAML object version 2.0

        Parameters:

        Returns:
            Nothing: Updates self.syaml(obj) if needed
        """
        v = get_version(self.syaml)
        if v not in ["2.0"]:
            self.module.fail_json(f"Version is not 2.0: {v}")

        backing_store = self._get_backingstore()
        if backing_store not in [
            "kubernetes",
            "vault",
            "none",
        ]:  # we currently only support vault
            self.module.fail_json(
                f"Currently only the 'vault', 'kubernetes' and 'none' backingStores are supported: {backing_store}"
            )

        (ret, msg) = self._validate_secrets()
        if not ret:
            self.module.fail_json(msg)

    def _process_secret_value(self, value):
        """
        Override base class to add YAML sanitization
        """
        return self._sanitize_yaml_value(value)

    def _inject_field(self, secret_name, f):
        on_missing_value = self._get_field_on_missing_value(f)
        override = self._get_field_override(f)
        kind = self._get_field_kind(f)
        b64 = self._get_field_base64(f)

        if kind in ["value", ""]:
            if on_missing_value == "generate":
                self.parsed_secrets[secret_name]["generate"].append(f["name"])
                if self._get_backingstore() != "vault":
                    self.module.fail_json(
                        "You cannot have onMissingValue set to 'generate' unless using vault backingstore "
                        f"for secret {secret_name} field {f['name']}"
                    )
                else:
                    if kind in ["path", "ini_file"]:
                        self.module.fail_json(
                            "You cannot have onMissingValue set to 'generate' with a path or ini_file"
                            f" for secret {secret_name} field {f['name']}"
                        )

                vault_policy = f.get("vaultPolicy", "validatedPatternDefaultPolicy")

                if override:
                    self.parsed_secrets[secret_name]["override"].append(f["name"])

                if b64:
                    self.parsed_secrets[secret_name]["base64"].append(f["name"])

                self.parsed_secrets[secret_name]["fields"][f["name"]] = None
                self.parsed_secrets[secret_name]["vault_policies"][
                    f["name"]
                ] = vault_policy

                return

            # If we're not generating the secret inside the vault directly we either read it from the file ("error")
            # or we are prompting the user for it
            secret = self._get_secret_value(secret_name, f)
            if b64:
                secret = base64.b64encode(secret.encode()).decode("utf-8")
                self.parsed_secrets[secret_name]["base64"].append(f["name"])

            self.parsed_secrets[secret_name]["fields"][f["name"]] = secret

        elif kind == "path":  # path. we upload files
            path = self._get_file_path(secret_name, f)
            self.parsed_secrets[secret_name]["paths"][f["name"]] = path

            binfile = False

            # Default to UTF-8
            try:
                secret = open(path, encoding="utf-8").read()
            except UnicodeDecodeError:
                secret = open(path, "rb").read()
                binfile = True

            if b64:
                self.parsed_secrets[secret_name]["base64"].append(f["name"])
                if binfile:
                    secret = base64.b64encode(bytes(secret)).decode("utf-8")
                else:
                    secret = base64.b64encode(secret.encode()).decode("utf-8")

            self.parsed_secrets[secret_name]["fields"][f["name"]] = secret
        elif kind == "ini_file":  # ini_file. we parse an ini_file
            ini_file = os.path.expanduser(f.get("ini_file"))
            ini_section = f.get("ini_section", "default")
            ini_key = f.get("ini_key")
            secret = get_ini_value(ini_file, ini_section, ini_key)
            if b64:
                self.parsed_secrets[secret_name]["base64"].append(f["name"])
                secret = base64.b64encode(secret.encode()).decode("utf-8")

            self.parsed_secrets[secret_name]["ini_file"][f["name"]] = {
                "ini_file": ini_file,
                "ini_section": ini_section,
                "ini_key": ini_key,
            }
            self.parsed_secrets[secret_name]["fields"][f["name"]] = secret

        return

    def get_unique_vault_prefixes(self):
        """
        Extract all unique vault prefixes from parsed secrets.

        This is useful for creating fine-grained Vault policies for each
        unique prefix path (e.g., apps/qtodo, hub/infra/keycloak).

        Returns:
            list: Sorted list of unique vault prefixes
        """
        prefixes = set()
        for secret in self.parsed_secrets.values():
            for prefix in secret.get("vault_prefixes", []):
                prefixes.add(prefix)
        return sorted(list(prefixes))
