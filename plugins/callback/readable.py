# -*- coding: utf-8 -*-
# Copyright (c) 2023, Al Bowles <@akatch>
# Copyright (c) 2012-2014, Michael DeHaan <michael.dehaan@gmail.com>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

DOCUMENTATION = r"""
name: readable
type: stdout
author: Al Bowles (@akatch), tweaked by Michele Baldessari & Drew Minnear
short_description: condensed Ansible output specific to Validated Patterns
description:
  - Consolidated Ansible output in the style of LINUX/UNIX startup logs.
extends_documentation_fragment:
  - default_callback
requirements:
  - set as stdout in configuration
"""

from ansible import constants as C
from ansible.module_utils.common.text.converters import to_text
from ansible.plugins.callback.default import CallbackModule as CallbackModule_default


class CallbackModule(CallbackModule_default):
    """
    Design goals:
    - Print consolidated output that looks like a *NIX startup log
    - Defaults should avoid displaying unnecessary information wherever possible
    """

    CALLBACK_VERSION = 1.0
    CALLBACK_TYPE = "stdout"
    CALLBACK_NAME = "rhvp.cluster_utils.readable"

    def _run_is_verbose(self, result):
        return (
            self._display.verbosity > 0 or "_ansible_verbose_always" in result._result
        ) and "_ansible_verbose_override" not in result._result

    def _get_task_display_name(self, task):
        """Return task display name, or None for include tasks."""
        name = task.get_name().strip().split(" : ")[-1]
        return None if name.startswith("include") else name

    def _preprocess_result(self, result):
        self.delegated_vars = result._result.get("_ansible_delegated_vars", None)
        self._handle_exception(
            result._result, use_stderr=self.get_option("display_failed_stderr")
        )
        self._handle_warnings(result._result)

    def _process_result_output(self, result, msg):
        # task_host = f"{result._host.get_name()} "
        task_host = ""
        task_result = f"{task_host}{msg}"

        if self._run_is_verbose(result):
            task_result = (
                f"{task_host}{msg}: {self._dump_results(result._result, indent=4)}"
            )
            return task_result

        if self.delegated_vars:
            task_delegate_host = self.delegated_vars["ansible_host"]
            task_result = f"{task_host}-> {task_delegate_host} {msg}"

        if (
            result._result.get("msg")
            and result._result.get("msg") != "All items completed"
        ):
            task_result += f" | msg: {to_text(result._result.get('msg'))}"

        if result._result.get("stdout"):
            task_result += f" | stdout: {result._result.get('stdout')}"

        if result._result.get("stderr"):
            task_result += f" | stderr: {result._result.get('stderr')}"

        return task_result

    def _display_task_start(self, task, suffix=""):
        """Display task start message with optional suffix (e.g., 'via handler')."""
        name = self._get_task_display_name(task)
        if name is None:
            return
        check_mode = (
            " (check mode)"
            if task.check_mode and self.get_option("check_mode_markers")
            else ""
        )
        suffix_str = f" ({suffix})" if suffix else ""
        self._display.display(f"{name}{suffix_str}{check_mode}...", newline=False)

    def v2_playbook_on_task_start(self, task, is_conditional):
        self._display_task_start(task)

    def v2_playbook_on_handler_task_start(self, task):
        self._display_task_start(task, suffix="via handler")

    def v2_playbook_on_play_start(self, play):
        name = play.get_name().strip()
        check_mode = play.check_mode and self.get_option("check_mode_markers")

        if name and play.hosts:
            check_str = " (in check mode)" if check_mode else ""
            msg = f"\n- {name}{check_str} on hosts: {','.join(play.hosts)} -"
        else:
            msg = "- check mode -" if check_mode else "---"

        self._display.display(msg)

    def v2_runner_on_skipped(self, result, ignore_errors=False):
        if not self.get_option("display_skipped_hosts"):
            return
        self._preprocess_result(result)
        task_result = self._process_result_output(result, "skipped")
        self._display.display(f"  {task_result}", C.COLOR_SKIP)

    def _build_msg_with_item(self, base_msg, result):
        """Build message with optional item label."""
        item_value = self._get_item_label(result._result)
        return f"{base_msg} | item: {item_value}" if item_value else base_msg

    def v2_runner_on_failed(self, result, ignore_errors=False):
        if ignore_errors:
            self._display.display("  error (ignored)", C.COLOR_WARN)
            return
        self._preprocess_result(result)
        msg = self._build_msg_with_item("failed", result)
        task_result = self._process_result_output(result, msg)
        self._display.display(
            f"  {task_result}",
            C.COLOR_ERROR,
            stderr=self.get_option("display_failed_stderr"),
        )

    def v2_runner_on_ok(self, result, msg="ok", display_color=C.COLOR_OK):
        self._preprocess_result(result)

        # Handle debug tasks specially
        if result._task.action in (
            "debug",
            "ansible.builtin.debug",
            "assert",
            "ansible.builtin.assert",
            "command",
            "ansible.builtin.command",
            "shell",
            "ansible.builtin.shell",
        ):
            debug_msg = result._result.get("msg", "")
            if debug_msg:
                self._display.display(f"\n{debug_msg}", C.COLOR_VERBOSE)
            return

        if result._result.get("changed"):
            msg = self._build_msg_with_item("done", result)
            display_color = C.COLOR_CHANGED
        elif not self.get_option("display_ok_hosts"):
            return

        task_result = self._process_result_output(result, msg)
        self._display.display(f"  {task_result}", display_color)

    def v2_runner_item_on_skipped(self, result):
        self.v2_runner_on_skipped(result)

    def v2_runner_item_on_failed(self, result):
        self.v2_runner_on_failed(result, ignore_errors=result._task.ignore_errors)

    def v2_runner_item_on_ok(self, result):
        self.v2_runner_on_ok(result)

    def v2_runner_on_unreachable(self, result):
        self._preprocess_result(result)
        task_result = self._process_result_output(result, "unreachable")
        self._display.display(
            f"  {task_result}",
            C.COLOR_UNREACHABLE,
            stderr=self.get_option("display_failed_stderr"),
        )

    def v2_on_file_diff(self, result):
        return

    def v2_playbook_on_stats(self, stats):
        return

    def v2_playbook_on_no_hosts_matched(self):
        self._display.display("  No hosts found!", color=C.COLOR_DEBUG)

    def v2_playbook_on_no_hosts_remaining(self):
        self._display.display("  Ran out of hosts!", color=C.COLOR_ERROR)

    def v2_playbook_on_start(self, playbook):
        return

    def v2_runner_retry(self, result):
        msg = f"  Retrying... ({result._result['attempts']} of {result._result['retries']})"
        if self._run_is_verbose(result):
            msg += f"Result was: {self._dump_results(result._result)}"
        self._display.display(msg, color=C.COLOR_DEBUG)
