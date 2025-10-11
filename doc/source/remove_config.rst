==============================
Remove configuration reference
==============================

This section describes the optional ``/etc/os-net-config/config.yaml`` YAML
``remove_config`` section and how entries are interpreted. The value of
``remove_config`` is a list of dict entries describing network devices to be
removed/cleaned up before applying the main ``network_config``.

Each entry describes a single device by name and logical type. The CLI parses
this section first and prepares provider-specific removal objects that can be
used by backend providers to delete configuration for the device.

Root element
------------

The root element is a top-level ``remove_config`` attribute, with an array of
entries, for example:

.. code-block:: yaml

  remove_config:
    - remove_type: ovs_bridge
      remove_name: br-ctlplane
    - remove_type: linux_bond
      remove_name: br-storage
    - remove_type: interface
      remove_name: nic3
    - remove_type: interface
      remove_name: nic4

Entry schema
------------

Each ``remove_config`` entry supports the following attributes:

- ``remove_name`` (string, required): The identifier of the device to remove. This
  can be the actual device name (e.g. ``br-ctlplane``, ``eth0``) or an abstract
  mapping name like ``nic1`` which will be resolved via the mapping file
  (see ``mapping.yaml``).
- ``remove_type`` (string, required): The logical device type. Common values
  include ``ovs_bridge``, ``ovs_interface``, ``linux_bridge``, ``interface``,
  or ``vlan``. Providers use this value to determine the correct removal logic.

The following attributes are automatically injected by the CLI when present in
other sections and are honored here as well:

Provider selection
------------------

When parsing a ``remove_config`` entry, the CLI attempts to detect first if the
legacy tool manages the device configuration to choose the appropriate removal path:

- If an ifcfg-style configuration file exists for the device
  (``/etc/sysconfig/network-scripts/ifcfg-<remove_name>``), the method of
  provider ``ifcfg`` will be invoked (legacy ifup/ifdown scripts).
- Otherwise, if an ``nmcli`` connection exists for the device, the remove method of
  ``nmstate`` provider will be invoked.
- If neither is detected, no action will be taken.

Examples
--------

Remove an Open vSwitch bridge and its members:

.. code-block:: yaml

  remove_config:
    - remove_type: ovs_bridge
      remove_name: br-ex
    - remove_type: interface
      remove_name: eno2
    - remove_type: vlan
      remove_name: vlan200

Remove a Linux bond and its members:

.. code-block:: yaml

  remove_config:
    - remove_type: linux_bond
      remove_name: bond0
    - remove_type: interface
      remove_name: eth3
    - remove_type: interface
      remove_name: eth4

Remove by abstract NIC mapping (mapping file resolves ``nic1``):

.. code-block:: yaml

  remove_config:
    - remove_type: ovs_interface
      remove_name: nic1

Processing order and behavior
-----------------------------

- ``remove_config`` is processed before ``network_config``.
- Entries are handled in the order listed.
- The removal objects are parsed and prepared by the CLI; the actual deletion is
  performed by provider-specific hooks

Notes
-----

- Use ``--remove-config`` flag to apply the remove_config.
- Legacy ``--cleanup`` flag should not be enabled with remove_config.
- Use ``--noop`` to preview what would be changed without applying.
- The ``purge-provider`` CLI option is separate and removes all configuration
  created by a given provider; it does not consume ``remove_config`` entries. 
