# -*- coding: utf-8 -*-

# Copyright 2025-2026 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.


from enum import IntEnum


class ExitCode(IntEnum):
    """Exit codes used by os-net-config."""

    SUCCESS = 0
    ERROR = 1
    FILES_CHANGED = 2
    FALLBACK_SUCCESS = 3
    FALLBACK_ERROR = 4
    MINIMUM_CONFIG_ERROR = 5
    REMOVE_CONFIG_ERROR = 6


def get_exit_code(detailed_exit_codes, ret_code):
    """Map return codes based on detailed mode.

    If detailed is True, return the given code. Otherwise, simplify the
    codes for backward compatibility.
    """
    if detailed_exit_codes:
        return ret_code

    exit_code_map = {
        ExitCode.SUCCESS: ExitCode.SUCCESS,
        ExitCode.ERROR: ExitCode.ERROR,
        ExitCode.FILES_CHANGED: ExitCode.SUCCESS,
        ExitCode.FALLBACK_SUCCESS: ExitCode.ERROR,
        ExitCode.FALLBACK_ERROR: ExitCode.ERROR,
        ExitCode.MINIMUM_CONFIG_ERROR: ExitCode.ERROR,
        ExitCode.REMOVE_CONFIG_ERROR: ExitCode.ERROR,
    }
    return exit_code_map.get(ret_code, ret_code)
