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
Ansible plugin module that loads secrets from a yaml file and pushes them
inside the HashiCorp Vault in an OCP cluster. The values-secrets.yaml file is
expected to be in the following format:
---
# version is optional. When not specified it is assumed it is 1.0
version: 1.0

# These secrets will be pushed in the vault at secret/hub/test The vault will
# have secret/hub/test with secret1 and secret2 as keys with their associated
# values (secrets)
secrets:
  test:
    secret1: foo
    secret2: bar

# This will create the vault key secret/hub/testfoo which will have two
# properties 'b64content' and 'content' which will be the base64-encoded
# content and the normal content respectively
files:
  testfoo: ~/ca.crt

# These secrets will be pushed in the vault at secret/region1/test The vault will
# have secret/region1/test with secret1 and secret2 as keys with their associated
# values (secrets)
secrets.region1:
  test:
    secret1: foo1
    secret2: bar1

# This will create the vault key secret/region2/testbar which will have two
# properties 'b64content' and 'content' which will be the base64-encoded
# content and the normal content respectively
files.region2:
  testbar: ~/ca.crt
"""

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = """
---
module: vault_load_secrets
short_description: Loads secrets into the HashiCorp Vault
version_added: "0.0.1"
author:
  - Michele Baldessari (@mbaldess)
  - Martin Jackson (@mhjacks)
description:
  - Takes a values-secret.yaml file and uploads the secrets into the HashiCorp Vault
options:
  values_secrets:
    description:
      - Path to the values-secrets file (only one of values_secrets and
        values_secrets_plaintext can be passed)
    required: false
    default: ''
    type: path
  values_secrets_plaintext:
    description:
      - The content of the values-secrets file (only one of values_secrets and
        values_secrets_plaintext can be passed)
    required: false
    default: ''
    type: path
  namespace:
    description:
      - Namespace where the vault is running
    required: false
    type: str
    default: vault
  pod:
    description:
      - Name of the vault pod to use to inject secrets
    required: false
    type: str
    default: vault-0
  basepath:
    description:
      - Vault's kv initial part of the path. This is only supported on version 1.0 of the
        secret format
    required: false
    type: str
    default: secret
  check_missing_secrets:
    description:
      - Validate the ~/values-secret.yaml file against the top-level
        values-secret-template.yaml and error out if secrets are missing
    required: false
    type: bool
    default: False
  values_secret_template:
    description:
      - Path of the values-secret-template.yaml file of the pattern
    required: false
    type: str
    default: ""
"""

RETURN = """
"""

EXAMPLES = """
- name: Loads secrets file into the vault of a cluster
  vault_load_secrets:
    values_secrets: ~/values-secret.yaml
"""
import os
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import missing_required_lib
from ansible_collections.rhvp.cluster_utils.plugins.module_utils.load_secrets_common import (
    get_version,
    filter_module_args)
from ansible_collections.rhvp.cluster_utils.plugins.module_utils.load_secrets_v1 import LoadSecretsV1
from ansible_collections.rhvp.cluster_utils.plugins.module_utils.load_secrets_v2 import LoadSecretsV2

try:
    import yaml
    HAS_YAML = True
    YAML_IMPORT_ERROR = None
except ImportError:
    HAS_YAML = False
    YAML_IMPORT_ERROR = traceback.format_exc()


def run(module):
    """Main ansible module entry point"""
    results = dict(changed=False)

    args = module.params
    values_secrets = args.get("values_secrets", "")
    values_secrets_plaintext = args.get("values_secrets_plaintext", "")
    if values_secrets != "" and values_secrets_plaintext != "":
        module.fail_json("Cannot pass both values_secret and values_secret_plaintext")

    values_secrets = args.get("values_secrets")
    basepath = args.get("basepath")
    namespace = args.get("namespace")
    pod = args.get("pod")
    check_missing_secrets = args.get("check_missing_secrets")
    values_secret_template = args.get("values_secret_template")

    if values_secrets != "" and not os.path.exists(values_secrets):
        results["failed"] = True
        results["error"] = f"Missing {values_secrets} file"
        results["msg"] = f"Values secrets file does not exist: {values_secrets}"
        module.exit_json(**results)

    # We were passed a filename (aka the unencrypted path)
    if values_secrets != "":
        with open(values_secrets, "r", encoding="utf-8") as file:
            syaml = yaml.safe_load(file.read())
        if syaml is None:
            syaml = {}
        elif isinstance(syaml, str):
            module.fail_json(f"Could not parse {values_secrets} file as yaml")
    elif values_secrets_plaintext != "":
        syaml = yaml.safe_load(values_secrets_plaintext)
        if syaml is None:
            syaml = {}
        elif isinstance(syaml, str):
            module.fail_json("Could not parse values_secrets_plaintext as yaml")
    else:
        module.fail_json("Both values_secrets and values_secrets_plaintext are unset")

    version = get_version(syaml)
    if version == "2.0":
        secret_obj = LoadSecretsV2(module, syaml, namespace, pod)
    elif version == "1.0":
        secret_obj = LoadSecretsV1(
            module,
            syaml,
            basepath,
            namespace,
            pod,
            values_secret_template,
            check_missing_secrets,
        )

    else:
        secret_obj = None
        module.fail_json(f"Version {version} is currently not supported")

    secret_obj.sanitize_values()
    nr_secrets = secret_obj.inject_secrets()
    results["failed"] = False
    results["changed"] = True
    results["msg"] = f"{nr_secrets} secrets injected"
    module.exit_json(**results)


def main():
    """Main entry point where the AnsibleModule class is instantiated"""

    # This would really be an exceptional circumstance
    if not HAS_YAML:
        module = AnsibleModule(argument_spec=dict(), supports_check_mode=True)
        module.fail_json(
            msg=missing_required_lib('yaml'),
            exception=YAML_IMPORT_ERROR)

    arg_spec = filter_module_args(yaml.safe_load(DOCUMENTATION)["options"])

    module = AnsibleModule(
        argument_spec=arg_spec,
        supports_check_mode=False,
    )
    run(module)


if __name__ == "__main__":
    main()
