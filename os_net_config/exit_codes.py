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
    """Exit codes used by os-net-config.

    Uses bitmask design where each bit indicates failure (1) or success (0).
    This allows combining multiple section results efficiently.

    Bit positions:
    - Bit 0: General error
    - Bit 1: Files changed (success indicator)
    - Bit 2: Network config failed
    - Bit 3: Fallback failed
    - Bit 4: Minimum config failed
    - Bit 5: Remove config failed
    - Bit 6: Purge failed
    - Bit 7: DCB config failed
    """

    SUCCESS = 0x0                    # 0b0000000 - All operations successful
    ERROR = 0x1                      # 0b0000001 - General error
    FILES_CHANGED = 0x2              # 0b0000010 - Files modified (success)

    # Failure bits for each section (bit set = failed)
    NETWORK_CONFIG_FAILED = 0x4      # 0b0000100 - Network config failed
    FALLBACK_FAILED = 0x8            # 0b0001000 - Fallback failed
    MINIMUM_CONFIG_FAILED = 0x10     # 0b0010000 - Minimum config failed
    REMOVE_CONFIG_FAILED = 0x20      # 0b0100000 - Remove config failed
    PURGE_FAILED = 0x40              # 0b1000000 - Purge failed
    DCB_CONFIG_FAILED = 0x80         # 0b10000000 - DCB config failed


def get_exit_code(detailed_exit_codes, ret_code):
    """Map return codes based on detailed mode.

    If detailed is True, return the given code. Otherwise, simplify to
    SUCCESS/ERROR based on failure bits.

    In the optimized bitmask design:
    - Any failure bit set (bits 0,2-6) = ERROR
    - Only SUCCESS (0) or FILES_CHANGED (bit 1) = SUCCESS
    """
    if detailed_exit_codes:
        return ret_code

    # Check for any failure bits (all bits except FILES_CHANGED)
    failure_mask = ~ExitCode.FILES_CHANGED  # All bits except bit 1

    if ret_code & failure_mask:
        return ExitCode.ERROR

    # Only SUCCESS or FILES_CHANGED remain
    return ExitCode.SUCCESS


def has_failures(ret_code):
    """Check if any failure bits are set in the return code.

    Returns:
        bool: True if any operation failed, False otherwise
    """
    failure_mask = ~ExitCode.FILES_CHANGED  # All bits except FILES_CHANGED
    return bool(ret_code & failure_mask)
