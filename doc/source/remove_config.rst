==============================
Remove configuration reference
==============================

This section describes the optional ``/etc/os-net-config/config.yaml`` YAML
``remove_config`` section and how entries are interpreted. The value of
``remove_config`` is a list of dict entries describing network devices to be
removed/cleaned up before applying the main ``network_config``.

Each entry describes a single device by name and logical type. The devices
provided in the list will be unconfigured + removed, irrespective of the
tool used to configure the device.

Devices removed in the ``remove_config`` section can be reconfigured
with different settings in the ``network_config`` section. This allows users to
cleanly remove old configurations before applying new ones.

Entry schema
------------

The remove_config section has a top-level ``remove_config`` attribute, with an
array of entries, for example:

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

Each ``remove_config`` entry supports the following attributes:

- ``remove_name`` (string, required): The identifier of the device to remove. This
  can be the actual device name (e.g. ``br-ctlplane``, ``eth0``) or an abstract
  mapping name like ``nic1`` which will be resolved via the mapping file
  (see ``mapping.yaml``).
- ``remove_type`` (string, required): The logical device type. Common values
  include ``ovs_bridge``, ``ovs_interface``, ``linux_bond``, ``interface``,
  or ``vlan``. Providers use this value to determine the correct removal logic.

**Important: Hierarchical Device Removal**

When removing complex network objects, you must explicitly list ALL member and
child devices in the ``remove_config`` section. Removing a parent object does
not automatically remove its members.

For example, if an OVS bridge ``br-data`` is configured with a bond ``bond-data``
as a member, and that bond contains two interfaces ``eth0`` and ``eth1``, then
to completely remove the bridge configuration, the ``remove_config`` section must
include separate entries for:

- The bridge itself (``br-data``)
- The bond (``bond-data``)
- Both member interfaces (``eth0`` and ``eth1``)

The provider will automatically process removals in the correct order (members
first, then parents), regardless of the order you specify in the configuration.

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

Notes
-----

- Use ``--remove-config`` flag to apply the remove_config section. This is the
  preferred method over ``--cleanup`` for explicit and controlled device removal.
- Use ``--noop`` to preview what would be removed without applying.
- The ``purge-provider`` CLI option is separate and removes all configuration
  created by a given provider; it does not consume ``remove_config`` entries. 
