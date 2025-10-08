# Copyright 2022 Red Hat, Inc.
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
import time

from ansible_collections.rhvp.cluster_utils.plugins.module_utils.load_secrets_common import (
    SecretsV2Base,
    find_dupes,
    get_ini_value,
    get_version,
)


class LoadSecretsV2(SecretsV2Base):

    def __init__(self, module, syaml, namespace, pod):
        super().__init__(module, syaml)
        self.namespace = namespace
        self.pod = pod

    def _run_command(self, command, attempts=1, sleep=3, checkrc=True):
        """
        Runs a command on the host ansible is running on. A failing command
        will raise an exception in this function directly (due to check=True)

        Parameters:
            command(str): The command to be run.
            attempts(int): Number of times to retry in case of Error (defaults to 1)
            sleep(int): Number of seconds to wait in between retry attempts (defaults to 3s)

        Returns:
            ret(subprocess.CompletedProcess): The return value from run()
        """
        for attempt in range(attempts):
            ret = self.module.run_command(
                command,
                check_rc=checkrc,
                use_unsafe_shell=True,
                environ_update=os.environ.copy(),
            )
            if ret[0] == 0:
                return ret
            if attempt >= attempts - 1:
                return ret
            time.sleep(sleep)

    def _get_backingstore(self):
        """
        Return the backingStore: of the parsed yaml object. If it does not exist
        return 'vault'

        Returns:
            ret(str): The value of the top-level 'backingStore:' key
        """
        return str(self.syaml.get("backingStore", "vault"))

    def _get_secrets(self):
        return self.syaml.get("secrets", {})

    def _validate_secrets(self):
        secrets = self._get_secrets()
        if len(secrets) == 0:
            self.module.fail_json("No secrets found")

        # Validate each secret and collect names for duplicate checking
        secret_names = []
        for secret in secrets:
            result = self._validate_secret(secret)
            if not result[0]:
                return result
            secret_names.append(secret["name"])

        # Check for duplicate secret names
        dupes = find_dupes(secret_names)
        if len(dupes) > 0:
            return (False, f"You cannot have duplicate secret names: {dupes}")

        return (True, "")

    def _validate_secret(self, secret):
        """Validate a single secret configuration"""
        # Check mandatory fields
        if "name" not in secret:
            return (False, f"Secret {secret} is missing name")

        secret_name = secret["name"]

        # Validate vault prefixes
        result = self._validate_vault_prefixes(secret)
        if not result[0]:
            return result

        # Validate fields
        result = self._validate_secret_fields(secret)
        if not result[0]:
            return result

        return (True, "")

    def _validate_vault_prefixes(self, secret):
        """Validate vault prefixes for a secret"""
        vault_prefixes = secret.get("vaultPrefixes", ["hub"])
        # This checks for the case when vaultPrefixes: is specified but empty
        if vault_prefixes is None or len(vault_prefixes) == 0:
            return (False, f"Secret {secret['name']} has empty vaultPrefixes")
        return (True, "")

    def _validate_secret_fields(self, secret):
        """Validate all fields for a secret"""
        fields = secret.get("fields", [])
        if len(fields) == 0:
            return (False, f"Secret {secret['name']} does not have any fields")

        # Validate each field and collect names for duplicate checking
        field_names = []
        for field in fields:
            result = self._validate_field(field)
            if not result[0]:
                return result
            field_names.append(field["name"])

        # Check for duplicate field names
        field_dupes = find_dupes(field_names)
        if len(field_dupes) > 0:
            return (False, f"You cannot have duplicate field names: {field_dupes}")

        return (True, "")

    def inject_vault_policies(self):
        for name, policy in self._get_vault_policies().items():
            cmd = (
                f"echo '{policy}' | oc exec -n {self.namespace} {self.pod} -i -- sh -c "
                f"'cat - > /tmp/{name}.hcl';"
                f"oc exec -n {self.namespace} {self.pod} -i -- sh -c 'vault write sys/policies/password/{name} "
                f" policy=@/tmp/{name}.hcl'"
            )
            self._run_command(cmd, attempts=3)

    def sanitize_values(self):
        """
        Sanitizes the secrets YAML object version 2.0

        Parameters:

        Returns:
            Nothing: Updates self.syaml(obj) if needed
        """
        v = get_version(self.syaml)
        if v != "2.0":
            self.module.fail_json(f"Version is not 2.0: {v}")

        backing_store = self._get_backingstore()
        if backing_store != "vault":  # we currently only support vault
            self.module.fail_json(
                f"Currently only the 'vault' backingStore is supported: {backing_store}"
            )
        (ret, msg) = self._validate_secrets()
        if not ret:
            self.module.fail_json(msg)

    def _vault_secret_attr_exists(self, mount, prefix, secret_name, attribute):
        cmd = (
            f"oc exec -n {self.namespace} {self.pod} -i -- sh -c "
            f'"vault kv get -mount={mount} -field={attribute} {prefix}/{secret_name}"'
        )
        # we ignore stdout and stderr
        (ret, *unused) = self._run_command(cmd, attempts=1, checkrc=False)
        if ret == 0:
            return True

        return False

    def _inject_field(self, secret_name, f, mount, prefixes, first=False):
        verb = "put" if first else "patch"
        kind = self._get_field_kind(f)

        match kind:
            case "value" | "":
                self._inject_value_field(secret_name, f, mount, prefixes, verb)
            case "path":
                self._inject_path_field(secret_name, f, mount, prefixes, verb)
            case "ini_file":
                self._inject_ini_field(secret_name, f, mount, prefixes, verb)

    def _inject_value_field(self, secret_name, f, mount, prefixes, verb):
        """Inject a value-based field into vault"""
        on_missing_value = self._get_field_on_missing_value(f)

        if on_missing_value == "generate":
            self._inject_generated_secret(secret_name, f, mount, prefixes, verb)
        else:
            self._inject_provided_secret(secret_name, f, mount, prefixes, verb)

    def _inject_generated_secret(self, secret_name, f, mount, prefixes, verb):
        """Generate and inject a secret using vault policy"""
        kind = self._get_field_kind(f)
        if kind == "path":
            self.module.fail_json(
                "You cannot have onMissingValue set to 'generate' with a path"
            )

        override = self._get_field_override(f)
        b64 = self._get_field_base64(f)
        vault_policy = f.get("vaultPolicy")

        gen_cmd = f"vault read -field=password sys/policies/password/{vault_policy}/generate"
        if b64:
            gen_cmd += " | base64 --wrap=0"

        for prefix in prefixes:
            # Skip if secret exists and override is False
            if not override and self._vault_secret_attr_exists(
                mount, prefix, secret_name, f["name"]
            ):
                continue

            cmd = (
                f"oc exec -n {self.namespace} {self.pod} -i -- sh -c "
                f"\"{gen_cmd} | vault kv {verb} -mount={mount} {prefix}/{secret_name} {f['name']}=-\""
            )
            self._run_command(cmd, attempts=3)

    def _inject_provided_secret(self, secret_name, f, mount, prefixes, verb):
        """Inject a user-provided secret value"""
        secret = self._get_secret_value(secret_name, f)
        secret = self._encode_secret_if_needed(secret, f)

        for prefix in prefixes:
            cmd = (
                f"oc exec -n {self.namespace} {self.pod} -i -- sh -c "
                f"\"vault kv {verb} -mount={mount} {prefix}/{secret_name} {f['name']}='{secret}'\""
            )
            self._run_command(cmd, attempts=3)

    def _inject_path_field(self, secret_name, f, mount, prefixes, verb):
        """Inject a file-based field into vault"""
        path = self._get_file_path(secret_name, f)
        b64_cmd = "| base64 --wrap=0 " if self._get_field_base64(f) else ""

        for prefix in prefixes:
            cmd = (
                f"cat '{path}' | oc exec -n {self.namespace} {self.pod} -i -- sh -c "
                f"'cat - {b64_cmd}> /tmp/vcontent'; "
                f"oc exec -n {self.namespace} {self.pod} -i -- sh -c '"
                f"vault kv {verb} -mount={mount} {prefix}/{secret_name} {f['name']}=@/tmp/vcontent; "
                f"rm /tmp/vcontent'"
            )
            self._run_command(cmd, attempts=3)

    def _inject_ini_field(self, secret_name, f, mount, prefixes, verb):
        """Inject an INI file-based field into vault"""
        ini_file = os.path.expanduser(f.get("ini_file"))
        ini_section = f.get("ini_section", "default")
        ini_key = f.get("ini_key")

        secret = get_ini_value(ini_file, ini_section, ini_key)
        secret = self._encode_secret_if_needed(secret, f)

        for prefix in prefixes:
            cmd = (
                f"oc exec -n {self.namespace} {self.pod} -i -- sh -c "
                f"\"vault kv {verb} -mount={mount} {prefix}/{secret_name} {f['name']}='{secret}'\""
            )
            self._run_command(cmd, attempts=3)

    def _encode_secret_if_needed(self, secret, f):
        """Apply base64 encoding if required"""
        if self._get_field_base64(f):
            return base64.b64encode(secret.encode()).decode("utf-8")
        return secret

    # This assumes that self.sanitize_values() has already been called
    # so we do a lot less validation as it has already happened
    def inject_secrets(self):
        # This must come first as some passwords might depend on vault policies to exist.
        # It is a noop when no policies are defined
        self.inject_vault_policies()
        secrets = self._get_secrets()

        total_secrets = 0  # Counter for all the secrets uploaded
        for s in secrets:
            counter = 0  # This counter is to use kv put on first secret and kv patch on latter
            sname = s.get("name")
            fields = s.get("fields", [])
            mount = s.get("vaultMount", "secret")
            vault_prefixes = s.get("vaultPrefixes", ["hub"])
            for i in fields:
                self._inject_field(sname, i, mount, vault_prefixes, counter == 0)
                counter += 1
                total_secrets += 1

        return total_secrets
