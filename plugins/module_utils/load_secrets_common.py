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
Module that implements some common functions
"""
from __future__ import absolute_import, division, print_function

__metaclass__ = type

import configparser
import getpass
import os
from collections.abc import MutableMapping

default_vp_vault_policies = {
    "validatedPatternDefaultPolicy": (
        "length=20\n"
        'rule "charset" { charset = "abcdefghijklmnopqrstuvwxyz" min-chars = 1 }\n'
        'rule "charset" { charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" min-chars = 1 }\n'
        'rule "charset" { charset = "0123456789" min-chars = 1 }\n'
        'rule "charset" { charset = "!@#%^&*" min-chars = 1 }\n'
    )
}


def find_dupes(array):
    """
    Returns duplicate items in a list

    Parameters:
        l(list): Array to check for duplicate entries

    Returns:
        dupes(list): Array containing all the duplicates and [] is there are none
    """
    seen = set()
    dupes = []
    for x in array:
        if x in seen:
            dupes.append(x)
        else:
            seen.add(x)
    return dupes


def get_version(syaml):
    """
    Return the version: of the parsed yaml object. If it does not exist
    return 1.0

    Returns:
        ret(str): The version value in of the top-level 'version:' key
    """
    return str(syaml.get("version", "1.0"))


def flatten(dictionary, parent_key=False, separator="."):
    """
    Turn a nested dictionary into a flattened dictionary and also
    drop any key that has 'None' as their value

    Parameters:
        dictionary(dict): The dictionary to flatten

        parent_key(str): The string to prepend to dictionary's keys

        separator(str): The string used to separate flattened keys

    Returns:

        dictionary: A flattened dictionary where the keys represent the
        path to reach the leaves
    """

    items = []
    for key, value in dictionary.items():
        new_key = str(parent_key) + separator + key if parent_key else key
        if isinstance(value, MutableMapping):
            items.extend(flatten(value, new_key, separator).items())
        elif isinstance(value, list):
            for k, v in enumerate(value):
                items.extend(flatten({str(k): v}, new_key).items())
        else:
            if value is not None:
                items.append((new_key, value))
    return dict(items)


def get_ini_value(inifile, inisection, inikey):
    """
    Return a value from an ini-file or 'None' if it does not exist

    Parameters:
        inifile(str): The path to the ini-file

        inisection(str): The section in the ini-file to look for the key

        inikey(str): The key to look up inside the ini-file's section

    Returns:

        obj: The value of the key or None if it does not exist
    """
    config = configparser.ConfigParser()
    config.read(inifile)
    return config.get(inisection, inikey, fallback=None)


def stringify_dict(input_dict):
    """
    Return a dict whose keys and values are all co-erced to strings, for creating labels and annotations in the
    python Kubernetes module

    Parameters:
        input_dict(dict): A dictionary of keys and values

    Returns:

        obj: The same dict in the same order but with the keys coerced to str
    """
    output_dict = {}

    for key, value in input_dict.items():
        output_dict[str(key)] = str(value)

    return output_dict


def filter_module_args(arg_spec):
    """
    Return a dict that is suitable as an Ansible Module argument spec based on a DOCUMENTATION string from
    the options section.
    Specific changes that are made to options include removing the description key, if it exists
    and adding a no_log setting. 'parsed_secrets' actually contains secrets but the other fields do not.

    Without this function, sanity tests throw numerous errors because of improper argument specs.
    """
    for arg in arg_spec:
        # We only deal with meta-secrets in this module
        if arg == "parsed_secrets":
            arg_spec[arg]["no_log"] = True
        elif "secret" in arg:
            arg_spec[arg]["no_log"] = False

        try:
            del arg_spec[arg]["description"]
        except KeyError:
            pass

    return arg_spec


class SecretsV2Base:
    """
    Base class with common functionality for V2 secrets handling
    """

    def __init__(self, module, syaml):
        self.module = module
        self.syaml = syaml

    def _get_vault_policies(self, enable_default_vp_policies=True):
        # We start off with the hard-coded default VP policy and add the user-defined ones
        policies = default_vp_vault_policies.copy() if enable_default_vp_policies else {}
        policies.update(self.syaml.get("vaultPolicies", {}))
        return policies

    def _get_secrets(self):
        return self.syaml.get("secrets", [])

    def _get_field_on_missing_value(self, f):
        # By default if 'onMissingValue' is missing we assume we need to
        # error out whenever the value is missing
        return f.get("onMissingValue", "error")

    def _get_field_value(self, f):
        return f.get("value", None)

    def _get_field_path(self, f):
        return f.get("path", None)

    def _get_field_ini_file(self, f):
        return f.get("ini_file", None)

    def _get_field_kind(self, f):
        # value: null will be interpreted with None, so let's just
        # check for the existence of the field, as we use 'value: null' to say
        # "we want a value/secret and not a file path"
        found = []
        for i in ["value", "path", "ini_file"]:
            if i in f:
                found.append(i)

        if len(found) > 1:  # you can only have one of value, path and ini_file
            self.module.fail_json(f"Both '{found[0]}' and '{found[1]}' cannot be used")

        if len(found) == 0:
            return ""
        return found[0]

    def _get_field_prompt(self, f):
        return f.get("prompt", None)

    def _get_field_base64(self, f):
        return bool(f.get("base64", False))

    def _get_field_override(self, f):
        return bool(f.get("override", False))

    def _validate_field(self, f):
        # These fields are mandatory
        try:
            unused = f["name"]
        except KeyError:
            return (False, f"Field {f} is missing name")

        on_missing_value = self._get_field_on_missing_value(f)
        if on_missing_value not in ["error", "generate", "prompt"]:
            return (False, f"onMissingValue: {on_missing_value} is invalid")

        value = self._get_field_value(f)
        path = self._get_field_path(f)
        ini_file = self._get_field_ini_file(f)
        kind = self._get_field_kind(f)
        if kind == "ini_file":
            # if we are using ini_file then at least ini_key needs to be defined
            # ini_section defaults to 'default' when omitted
            ini_key = f.get("ini_key", None)
            if ini_key is None:
                return (
                    False,
                    "ini_file requires at least ini_key to be defined",
                )

        # Test if base64 is a correct boolean (defaults to False)
        unused = self._get_field_base64(f)
        unused = self._get_field_override(f)

        vault_policy = f.get("vaultPolicy", None)
        if vault_policy is not None and vault_policy not in self._get_vault_policies():
            return (
                False,
                f"Secret has vaultPolicy set to {vault_policy} but no such policy exists",
            )

        if on_missing_value in ["error"]:
            if (
                (value is None or len(value) < 1)
                and (path is None or len(path) < 1)
                and (ini_file is None or len(ini_file) < 1)
            ):
                return (
                    False,
                    "Secret has onMissingValue set to 'error' and has neither value nor path nor ini_file set",
                )
            if path is not None and not os.path.isfile(os.path.expanduser(path)):
                return (False, f"Field has non-existing path: {path}")

            if ini_file is not None and not os.path.isfile(
                os.path.expanduser(ini_file)
            ):
                return (False, f"Field has non-existing ini_file: {ini_file}")

            if "override" in f:
                return (
                    False,
                    "'override' attribute requires 'onMissingValue' to be set to 'generate'",
                )

        if on_missing_value in ["generate"]:
            if value is not None:
                return (
                    False,
                    "Secret has onMissingValue set to 'generate' but has a value set",
                )
            if path is not None:
                return (
                    False,
                    "Secret has onMissingValue set to 'generate' but has a path set",
                )
            if vault_policy is None:
                return (
                    False,
                    "Secret has no vaultPolicy but onMissingValue is set to 'generate'",
                )

        if on_missing_value in ["prompt"]:
            # When we prompt, the user needs to set one of the following:
            # - value: null # prompt for a secret without a default value
            # - value: 123 # prompt for a secret but use a default value
            # - path: null # prompt for a file path without a default value
            # - path: /tmp/ca.crt # prompt for a file path with a default value
            if "value" not in f and "path" not in f:
                return (
                    False,
                    "Secret has onMissingValue set to 'prompt' but has no value nor path fields",
                )

            if "override" in f:
                return (
                    False,
                    "'override' attribute requires 'onMissingValue' to be set to 'generate'",
                )

        return (True, "")

    def _get_secret_value(self, name, field):
        on_missing_value = self._get_field_on_missing_value(field)
        # We checked for errors in _validate_secrets() already
        match on_missing_value:
            case "error":
                value = field.get("value")
                # Allow subclasses to override value processing
                return self._process_secret_value(value)
            case "prompt":
                prompt = self._get_field_prompt(field)
                if prompt is None:
                    prompt = f"Type secret for {name}/{field['name']}: "
                value = self._get_field_value(field)
                if value is not None:
                    prompt += f" [{value}]"
                prompt += ": "
                return getpass.getpass(prompt)
            case _:
                return None

    def _process_secret_value(self, value):
        """
        Process a secret value. Can be overridden by subclasses.
        """
        return value

    def _get_file_path(self, name, field):
        on_missing_value = self._get_field_on_missing_value(field)
        match on_missing_value:
            case "error":
                return os.path.expanduser(field.get("path"))
            case "prompt":
                prompt = self._get_field_prompt(field)
                path = self._get_field_path(field)
                if path is None:
                    path = ""

                if prompt is None:
                    text = f"Type path for file {name}/{field['name']} [{path}]: "
                else:
                    text = f"{prompt} [{path}]: "

                newpath = getpass.getpass(text)
                if newpath == "":  # Set the default if no string was entered
                    newpath = path

                if os.path.isfile(os.path.expanduser(newpath)):
                    return newpath
                self.module.fail_json(f"File {newpath} not found, exiting")
            case _:
                self.module.fail_json("File with wrong onMissingValue")
