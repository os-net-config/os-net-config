# -*- coding: utf-8 -*-

# Copyright 2014-2015 Red Hat, Inc.
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

import json
import logging
import os

from oslo_concurrency import processutils

from os_net_config import objects
from os_net_config import utils


logger = logging.getLogger(__name__)


class NotImplemented(Exception):
    pass


class ConfigurationError(Exception):
    pass


class NetConfig(object):
    """Common network config methods class."""

    def __init__(self, noop=False, root_dir=''):
        self.noop = noop
        self.log_prefix = "NOOP: " if noop else ""
        self.root_dir = root_dir
        self.errors = []

    def del_object(self, obj):
        if isinstance(obj, objects.RouteTable):
            self.del_route_table(obj)
        elif isinstance(obj, objects.Interface):
            self.del_interface(obj)
        elif isinstance(obj, objects.Vlan):
            self.del_vlan(obj)
        elif isinstance(obj, objects.IvsInterface):
            self.del_ivs_interface(obj)
        elif isinstance(obj, objects.NfvswitchInternal):
            self.del_nfvswitch_internal(obj)
        elif isinstance(obj, objects.OvsBridge):
            for member in obj.members:
                self.del_object(member)
            self.del_bridge(obj)
        elif isinstance(obj, objects.OvsUserBridge):
            for member in obj.members:
                self.del_object(member)
            self.del_ovs_user_bridge(obj)
        elif isinstance(obj, objects.IvsBridge):
            for member in obj.members:
                self.del_object(member)
            self.del_ivs_bridge(obj)
        elif isinstance(obj, objects.NfvswitchBridge):
            for member in obj.members:
                self.del_object(member)
            self.del_nfvswitch_bridge(obj)
        elif isinstance(obj, objects.OvsBond):
            self.del_bond(obj)
            for member in obj.members:
                self.del_object(member)
        elif isinstance(obj, objects.LinuxBond):
            for member in obj.members:
                self.del_object(member)
            self.del_linux_bond(obj)
        elif isinstance(obj, objects.IbInterface):
            self.del_ib_interface(obj)
        elif isinstance(obj, objects.IbChildInterface):
            self.del_ib_child_interface(obj)
        elif isinstance(obj, objects.OvsDpdkPort):
            self.del_ovs_dpdk_port(obj)
        elif isinstance(obj, objects.OvsDpdkBond):
            self.del_ovs_dpdk_bond(obj)
        elif isinstance(obj, objects.SriovPF):
            self.del_sriov_pf(obj)
        elif isinstance(obj, objects.SriovVF):
            self.del_sriov_vf(obj)
        else:
            obj_type = json.get("type")
            logger.error(f'del_object not handled for {obj_type}')

    def enable_migration():
        logger.info('Migration is not supported for this provider')
        return

    def roll_back_migration(self):
        logger.info('roll back migration is not supported for this provider')
        return

    def clean_migration(self):
        logger.info('clean migration is not supported for this provider')
        return

    def add_object(self, obj):
        """Convenience method to add any type of object to the network config.

           See objects.py.

        :param obj: The object to add.
        """
        if isinstance(obj, objects.RouteTable):
            self.add_route_table(obj)
        if isinstance(obj, objects.Interface):
            self.add_interface(obj)
        elif isinstance(obj, objects.Vlan):
            self.add_vlan(obj)
        elif isinstance(obj, objects.IvsInterface):
            self.add_ivs_interface(obj)
        elif isinstance(obj, objects.NfvswitchInternal):
            self.add_nfvswitch_internal(obj)
        elif isinstance(obj, objects.OvsBridge):
            self.add_bridge(obj)
            for member in obj.members:
                self.add_object(member)
        elif isinstance(obj, objects.OvsUserBridge):
            self.add_ovs_user_bridge(obj)
            for member in obj.members:
                self.add_object(member)
        elif isinstance(obj, objects.LinuxBridge):
            self.add_linux_bridge(obj)
            for member in obj.members:
                self.add_object(member)
        elif isinstance(obj, objects.IvsBridge):
            self.add_ivs_bridge(obj)
            for member in obj.members:
                self.add_object(member)
        elif isinstance(obj, objects.NfvswitchBridge):
            self.add_nfvswitch_bridge(obj)
            for member in obj.members:
                self.add_object(member)
        elif isinstance(obj, objects.OvsBond):
            self.add_bond(obj)
            for member in obj.members:
                self.add_object(member)
        elif isinstance(obj, objects.LinuxBond):
            self.add_linux_bond(obj)
            for member in obj.members:
                self.add_object(member)
        elif isinstance(obj, objects.LinuxTeam):
            self.add_linux_team(obj)
            for member in obj.members:
                self.add_object(member)
        elif isinstance(obj, objects.OvsTunnel):
            self.add_ovs_tunnel(obj)
        elif isinstance(obj, objects.OvsPatchPort):
            self.add_ovs_patch_port(obj)
        elif isinstance(obj, objects.IbInterface):
            self.add_ib_interface(obj)
        elif isinstance(obj, objects.IbChildInterface):
            self.add_ib_child_interface(obj)
        elif isinstance(obj, objects.OvsDpdkPort):
            self.add_ovs_dpdk_port(obj)
        elif isinstance(obj, objects.OvsDpdkBond):
            self.add_ovs_dpdk_bond(obj)
        elif isinstance(obj, objects.SriovPF):
            self.add_sriov_pf(obj)
        elif isinstance(obj, objects.SriovVF):
            self.add_sriov_vf(obj)
        elif isinstance(obj, objects.VppInterface):
            self.add_vpp_interface(obj)
        elif isinstance(obj, objects.VppBond):
            self.add_vpp_bond(obj)
            for member in obj.members:
                self.add_object(member)
        elif isinstance(obj, objects.ContrailVrouter):
            self.add_contrail_vrouter(obj)
        elif isinstance(obj, objects.ContrailVrouterDpdk):
            self.add_contrail_vrouter_dpdk(obj)
        elif isinstance(obj, objects.LinuxTap):
            self.add_linux_tap(obj)

    def add_route_table(self, route_table):
        """Add a route table object to the net config object.

        :param route_table: The RouteTable object to add.
        """
        raise NotImplementedError("add_route_table is not implemented.")

    def del_route_table(self, route_table):
        """Delete a route table object to the net config object.

        :param route_table: The RouteTable object to be deleted.
        """
        raise NotImplementedError("del_route_table is not implemented.")

    def add_interface(self, interface):
        """Add an Interface object to the net config object.

        :param interface: The Interface object to add.
        """
        raise NotImplementedError("add_interface is not implemented.")

    def del_interface(self, interface):
        """Delete the Interface object to the net config object.

        :param interface: The Interface object to be deleted.
        """
        raise NotImplementedError("del_interface is not implemented.")

    def add_vlan(self, vlan):
        """Add a Vlan object to the net config object.

        :param vlan: The vlan object to add.
        """
        raise NotImplementedError("add_vlan is not implemented.")

    def del_vlan(self, vlan):
        """Delete a Vlan object to the net config object.

        :param vlan: The vlan object to be deleted.
        """
        raise NotImplementedError("del_vlan is not implemented.")

    def add_bridge(self, bridge):
        """Add an OvsBridge object to the net config object.

        :param bridge: The OvsBridge object to add.
        """
        raise NotImplementedError("add_bridge is not implemented.")

    def del_bridge(self, bridge):
        """Delete an OvsBridge object to the net config object.

        :param bridge: The OvsBridge object to be deleted.
        """
        raise NotImplementedError("del_bridge is not implemented.")

    def add_ovs_user_bridge(self, bridge):
        """Add an OvsUserBridge object to the net config object.

        :param bridge: The OvsUserBridge object to add.
        """
        raise NotImplementedError("add_ovs_user_bridge is not implemented.")

    def del_ovs_user_bridge(self, bridge):
        """Delete an OvsUserBridge object to the net config object.

        :param bridge: The OvsUserBridge object to be deleted.
        """
        raise NotImplementedError("del_ovs_user_bridge is not implemented.")

    def add_linux_bridge(self, bridge):
        """Add a LinuxBridge object to the net config object.

        :param bridge: The LinuxBridge object to add.
        """
        raise NotImplementedError("add_linux_bridge is not implemented.")

    def add_ivs_bridge(self, bridge):
        """Add a IvsBridge object to the net config object.

        :param bridge: The IvsBridge object to add.
        """
        raise NotImplementedError("add_ivs_bridge is not implemented.")

    def del_ivs_bridge(self, bridge):
        """Delete a IvsBridge object to the net config object.

        :param bridge: The IvsBridge object to be deleted.
        """
        raise NotImplementedError("del_ivs_bridge is not implemented.")

    def add_nfvswitch_bridge(self, bridge):
        """Add a NfvswitchBridge object to the net config object.

        :param bridge: The NfvswitchBridge object to add.
        """
        raise NotImplementedError("add_nfvswitch_bridge is not implemented.")

    def del_nfvswitch_bridge(self, bridge):
        """Delete a NfvswitchBridge object to the net config object.

        :param bridge: The NfvswitchBridge object to be deleted.
        """
        raise NotImplementedError("del_nfvswitch_bridge is not implemented.")

    def add_bond(self, bond):
        """Add an OvsBond object to the net config object.

        :param bond: The OvsBond object to add.
        """
        raise NotImplementedError("add_bond is not implemented.")

    def del_bond(self, bond):
        """Delete an OvsBond object to the net config object.

        :param bond: The OvsBond object to deleted.
        """
        raise NotImplementedError("del_bond is not implemented.")

    def add_linux_bond(self, bond):
        """Add a LinuxBond object to the net config object.

        :param bond: The LinuxBond object to add.
        """
        raise NotImplementedError("add_linux_bond is not implemented.")

    def add_linux_team(self, team):
        """Add a LinuxTeam object to the net config object.

        :param team: The LinuxTeam object to add.
        """
        raise NotImplementedError("add_linux_team is not implemented.")

    def add_ovs_tunnel(self, tunnel):
        """Add a OvsTunnel object to the net config object.

        :param tunnel: The OvsTunnel object to add.
        """
        raise NotImplementedError("add_ovs_tunnel is not implemented.")

    def add_ovs_patch_port(self, ovs_patch_port):
        """Add a OvsPatchPort object to the net config object.

        :param ovs_patch_port: The OvsPatchPort object to add.
        """
        raise NotImplementedError("add_ovs_patch_port is not implemented.")

    def del_ovs_patch_port(self, ovs_patch_port):
        """Delete a OvsPatchPort object to the net config object.

        :param ovs_patch_port: The OvsPatchPort object to be deleted.
        """
        raise NotImplementedError("del_ovs_patch_port is not implemented.")

    def add_ib_interface(self, ib_interface):
        """Add an InfiniBand Interface object to the net config object.

        :param interface: The InfiniBand Interface object to add.
        """
        raise NotImplementedError("add_ib_interface is not implemented.")

    def del_ib_interface(self, ib_interface):
        """Delete an InfiniBand Interface object to the net config object.

        :param interface: The InfiniBand Interface object to be deleted.
        """
        raise NotImplementedError("del_ib_interface is not implemented.")

    def add_ib_child_interface(self, ib_child_interface):
        """Add an InfiniBand child interface object to the net config object.

        :param ib_child_interface: The InfiniBand child
        interface object to add.
        """
        raise NotImplementedError("add_ib_child_interface is not implemented.")

    def add_ovs_dpdk_port(self, ovs_dpdk_port):
        """Add a OvsDpdkPort object to the net config object.

        :param ovs_dpdk_port: The OvsDpdkPort object to add.
        """
        raise NotImplementedError("add_ovs_dpdk_port is not implemented.")

    def del_ovs_dpdk_port(self, ovs_dpdk_port):
        """Delete a OvsDpdkPort object to the net config object.

        :param ovs_dpdk_port: The OvsDpdkPort object to be deleted.
        """
        raise NotImplementedError("del_ovs_dpdk_port is not implemented.")

    def add_ovs_dpdk_bond(self, ovs_dpdk_bond):
        """Add a OvsDpdkBond object to the net config object.

        :param ovs_dpdk_bond: The OvsDpdkBond object to add.
        """
        raise NotImplementedError("add_ovs_dpdk_bond is not implemented.")

    def del_ovs_dpdk_bond(self, ovs_dpdk_bond):
        """Delete a OvsDpdkBond object to the net config object.

        :param ovs_dpdk_bond: The OvsDpdkBond object to be deleted.
        """
        raise NotImplementedError("del_ovs_dpdk_bond is not implemented.")

    def add_sriov_pf(self, sriov_pf):
        """Add a SriovPF object to the net config object.

        :param sriov_pf: The SriovPF object to add.
        """
        raise NotImplementedError("add_sriov_pf is not implemented.")

    def del_sriov_pf(self, sriov_pf):
        """Delete a SriovPF object to the net config object.

        :param sriov_pf: The SriovPF object to be deleted.
        """
        raise NotImplementedError("del_sriov_pf is not implemented.")

    def add_sriov_vf(self, sriov_vf):
        """Add a SriovVF object to the net config object.

        :param sriov_vf: The SriovVF object to add.
        """
        raise NotImplementedError("add_sriov_vf is not implemented.")

    def del_sriov_vf(self, sriov_vf):
        """Delete a SriovVF object to the net config object.

        :param sriov_vf: The SriovVF object to be deleted.
        """
        raise NotImplementedError("del_sriov_vf is not implemented.")

    def add_vpp_interface(self, vpp_interface):
        """Add a VppInterface object to the net config object.

        :param vpp_interface: The VppInterface object to add.
        """
        raise NotImplementedError("add_vpp_interface is not implemented.")

    def add_vpp_bond(self, vpp_bond):
        """Add a VppBond object to the net config object.

        :param vpp_bond: The VppBond object to add.
        """
        raise NotImplementedError("add_vpp_bond is not implemented.")

    def add_contrail_vrouter(self, contrail_vrouter):
        """Add a ContrailVrouter object to the net config object.

        :param contrail_vrouter:
            The ContrailVrouter object to add.
        """
        raise NotImplementedError("add_contrail_vrouter is not implemented.")

    def add_contrail_vrouter_dpdk(self, contrail_vrouter_dpdk):
        """Add a ContrailVrouterDpdk object to the net config object.

        :param contrail_vrouter_dpdk:
            The ContrailVrouterDpdk object to add.
        """
        raise NotImplementedError(
            "add_contrail_vrouter_dpdk is not implemented.")

    def add_linux_tap(self, linux_tap):
        """Add a LinuxTap object to the net config object.

        :param linux_tap:
            The LinuxTap object to add.
        """
        raise NotImplementedError(
            "add_linux_tap is not implemented.")

    def apply(self, cleanup=False):
        """Apply the network configuration.

        :param cleanup: A boolean which indicates whether any undefined
            (existing but not present in the object model) interfaces
            should be disabled and deleted.
        :returns: a dict of the format: filename/data which contains info
            for each file that was changed (or would be changed if in --noop
            mode).
        """
        raise NotImplementedError("apply is not implemented.")

    def execute(self, msg, cmd, *args, **kwargs):
        """Print a message and run a command.

        Print a message and run a command with processutils
        in noop mode, this just prints a message.
        """
        logger.info('%s%s' % (self.log_prefix, msg))
        if not self.noop:
            out, err = processutils.execute(cmd, *args, **kwargs)
            if err:
                logger.error(f"stderr : {err}")
            if out:
                logger.debug(f"stdout : {out}")

    def write_config(self, filename, data, msg=None):
        msg = msg or "Writing config %s" % filename
        logger.info('%s%s' % (self.log_prefix, msg))
        if not self.noop:
            utils.write_config(filename, data)

    def remove_config(self, filename, msg=None):
        msg = msg or "Removing config %s" % filename
        logger.info('%s%s' % (self.log_prefix, msg))
        if not self.noop:
            os.remove(filename)

    def ifdown(self, interface, iftype='interface'):
        msg = 'running ifdown on %s: %s' % (iftype, interface)
        self.execute(msg, '/sbin/ifdown', interface, check_exit_code=False)
        if utils.is_active_nic(interface):
            msg = '%s %s is up, trying with ip command' % (iftype, interface)
            self.execute(msg, '/sbin/ip',
                         'link', 'set', 'dev', interface, 'down')

    def ifup(self, interface, iftype='interface'):
        """Run 'ifup' on the specified interface

        If a failure occurs when bringing up the interface it will be saved
        to self.errors for later handling.  This allows callers to continue
        trying to bring up interfaces even if one fails.

        :param interface: The name of the interface to be started.
        :param iftype: The type of the interface.
        """
        msg = 'running ifup on %s: %s' % (iftype, interface)
        try:
            self.execute(msg, '/sbin/ifup', interface)
        except processutils.ProcessExecutionError as e:
            self.errors.append(e)

    def ifrename(self, oldname, newname):
        msg = 'renaming %s to %s: ' % (oldname, newname)
        # ifdown isn't enough when renaming, we need the link down
        for name in (oldname, newname):
            if utils.is_active_nic(name):
                self.execute(msg, '/sbin/ip',
                             'link', 'set', 'dev', name, 'down')
                self.execute(msg, '/sbin/ip',
                             'link', 'set', 'dev', name, 'link', 'down')
        self.execute(msg, '/sbin/ip',
                     'link', 'set', 'dev', oldname, 'name', newname)
        self.execute(msg, '/sbin/ip',
                     'link', 'set', 'dev', newname, 'up')

    def ovs_appctl(self, action, *parameters, ignore_err=False):
        """Run 'ovs-appctl' with the specified action

         Its possible the command may fail due to timing if, for example,
         the command affects an interface and it the prior ifup command
         has not completed.  So retry the command and if a failures still
         occurs save the error for later handling.

         :param action: The ovs-appctl action.
         :param parameters: Parameters to pass to ovs-appctl.
         """
        msg = 'Running ovs-appctl %s %s' % (action, parameters)
        try:
            self.execute(msg, '/bin/ovs-appctl', action, *parameters,
                         delay_on_retry=True, attempts=5)
        except processutils.ProcessExecutionError as e:
            if not ignore_err:
                self.errors.append(e)
