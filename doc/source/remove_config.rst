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
    - dev_type: ovs_bridge
      dev_name: br-ctlplane
    - dev_type: linux_bridge
      dev_name: br-storage

Entry schema
------------

Each ``remove_config`` entry supports the following attributes:

- ``dev_name`` (string, required): The identifier of the device to remove. This
  can be the actual device name (e.g. ``br-ctlplane``, ``eth0``) or an abstract
  mapping name like ``nic1`` which will be resolved via the mapping file
  (see ``mapping.yaml``).
- ``dev_type`` (string, required): The logical device type. Common values
  include ``ovs_bridge``, ``ovs_interface``, ``linux_bridge``, ``linux_bond``,
  or ``vlan``. Providers use this value to determine the correct removal logic.

The following attributes are automatically injected by the CLI when present in
other sections and are honored here as well:

Provider selection
------------------

When parsing a ``remove_config`` entry, the CLI attempts to detect which tool
manages the device configuration to choose the appropriate removal path:

- If an ``nmcli`` connection exists for the device, the remove method of
  ``nmcli`` provider will be invoked.
- Otherwise, if an ifcfg-style configuration file exists
  (``/etc/sysconfig/network-scripts/ifcfg-<dev_name>``), the method of
  provider ``ifcfg`` will be invoked (legacy ifup/ifdown scripts).
- If neither is detected, no action will be taken.

Examples
--------

Remove an Open vSwitch bridge:

.. code-block:: yaml

  remove_config:
    - dev_type: ovs_bridge
      dev_name: br-ctlplane

Remove a Linux bridge:

.. code-block:: yaml

  remove_config:
    - dev_type: linux_bridge
      dev_name: br-storage

Remove by abstract NIC mapping (mapping file resolves ``nic1``):

.. code-block:: yaml

  remove_config:
    - dev_type: ovs_interface
      dev_name: nic1

Processing order and behavior
-----------------------------

- ``remove_config`` is processed before ``network_config``.
- Entries are handled in the order listed.
- The removal objects are parsed and prepared by the CLI; the actual deletion is
  performed by provider-specific hooks

Notes
-----

- Use ``--noop`` to preview what would be changed without applying.
- The ``purge-provider`` CLI option is separate and removes all configuration
  created by a given provider; it does not consume ``remove_config`` entries. 
