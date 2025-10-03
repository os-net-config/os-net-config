=====
Usage
=====

Backend Provider Detection
--------------------------

The ``--provider`` argument to ``os-net-config`` selects one of the available
backend providers:

- ``ifcfg`` Configure network interfaces using the ifcfg format
  ``/etc/sysconfig/network-scripts/`` files.
- ``eni`` Configure network interfaces using the Debian/Ubuntu
  ``/etc/network/interfaces`` format
- ``iproute`` (Not implemented)

When the ``--provider`` argument is not specified when calling
``os-net-config`` the provider will be chosen using the following rules:

1) If path ``/etc/sysconfig/network-scripts/`` exists, use the ``ifcfg``
   provider.

2) Otherwise if path ``/etc/network/`` exists, use the ``eni`` provider.

In these rules, if a path is specified for ``--root-dir`` this will be
prepended to the checked paths before doing the above tests.

Interface Mapping
-----------------

The file ``/etc/os-net-config/mapping.yaml`` can contain mappings from
interface identifiers to the actual interface names. A different mapping file can
be used by using the ``--mapping-file`` argument to ``os-net-config``.

This mapping allows consistent interface identifiers to be used in the config
without needing the full interface name which can vary across servers and
hardware changes. This also allows config to be performed for interfaces
which are in a ``DOWN`` state before configuration.

The format of the mapping.yaml is as follows:

  .. code-block:: yaml

    interface_mapping:
      nic1: enp0s20f0u2u1u2
      nic2: enp0s31f6

To assist in writing this file, the following command will generate a JSON
snippet with discovered interfaces::

    $ os-net-config --interfaces
    {'nic1': 'enp0s20f0u2u1u2', 'nic2': 'enp0s31f6'}

When the ``--persist-mapping`` argument is specified when calling
``os-net-config`` then the existing interfaces names will be permanently
renamed to their identifier name.

Network Configuration
---------------------

By default the file ``/etc/os-net-config/config.yaml`` will be sourced for
the network configuration, but an alternate file can be used with the
``--config-file`` argument. The following arguments change the behaviour
during configuration:

- ``--detailed-exit-codes`` If enabled, returns detailed exit codes using a
  bitmask design. If disabled, simplifies to standard SUCCESS (0) or ERROR (1).
- ``--exit-on-validation-errors`` Exit with an error if configuration
  file validation fails.
- ``--noop`` Return the configuration commands, without applying them.
- ``--no-activate`` Install the configuration but don't start/stop
  interfaces.
- ``--cleanup`` Cleanup unconfigured interfaces.

Exit Codes
----------

The os-net-config tool uses a bitmask-based exit code system that allows
combining multiple operation results efficiently. Each bit represents a
specific operation outcome:

**Detailed Exit Codes (--detailed-exit-codes enabled):**

============================ ===== =============================================
Exit Code                    Value Description
============================ ===== =============================================
SUCCESS                      0     All operations successful
ERROR                        1     General error
FILES_CHANGED                2     Files were modified (success indicator)
NETWORK_CONFIG_FAILED        4     Network configuration failed
FALLBACK_FAILED              8     Fallback configuration failed
MINIMUM_CONFIG_FAILED        16    Minimum configuration failed
REMOVE_CONFIG_FAILED         32    Remove configuration failed
PURGE_FAILED                 64    Purge operation failed
DCB_CONFIG_FAILED            128   DCB configuration failed
SCHEMA_VALIDATION_FAILED     256   Schema validation failed
============================ ===== =============================================

**Standard Exit Codes (--detailed-exit-codes disabled):**

=========== ===== ==============================================
Exit Code   Value Description
=========== ===== ==============================================
SUCCESS     0     All operations successful or only files changed
ERROR       1     Any operation failed
=========== ===== ==============================================

Exit codes can be combined using bitwise OR operations. For example, if both
network configuration fails and fallback configuration fails, the exit code would be
4 | 8 = 12.

The ``FILES_CHANGED`` (2) code is a success indicator showing that the tool
made modifications to the system configuration files.

Python Library
--------------

To use os-net-config in a project::

	import os_net_config