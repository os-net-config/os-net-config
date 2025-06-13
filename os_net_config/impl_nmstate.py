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

from libnmstate import error
from libnmstate import gen_diff
from libnmstate import netapplier
from libnmstate import netinfo
from libnmstate.schema import Bond
from libnmstate.schema import BondMode
from libnmstate.schema import DNS
from libnmstate.schema import Ethernet
from libnmstate.schema import Ethtool
from libnmstate.schema import InfiniBand
from libnmstate.schema import Interface
from libnmstate.schema import InterfaceIPv4
from libnmstate.schema import InterfaceIPv6
from libnmstate.schema import InterfaceState
from libnmstate.schema import InterfaceType
from libnmstate.schema import OVSBridge
from libnmstate.schema import OvsDB
from libnmstate.schema import OVSInterface
from libnmstate.schema import Route as NMRoute
from libnmstate.schema import RouteRule as NMRouteRule
from libnmstate.schema import VLAN
import logging
import netaddr
import os
import re
import yaml

import os_net_config
from os_net_config import common
from os_net_config import objects
from os_net_config import utils


logger = logging.getLogger(__name__)

# Import the raw NetConfig object so we can call its methods
netconfig = os_net_config.NetConfig()

DISPATCHER_SCRIPT_PREFIX = r"""
set +e
set -x
"""

# Script used to bind the VFs with appropriate drivers.
# VFs specified in `dpdk_vfs` will be bound with vfio-pci.
# VFs specified in `linux_vfs` will be bound with their default drivers
_VF_BIND_DRV_SCRIPT = r'''
dpdk_vfs="{dpdk_vfs}"
linux_vfs="{linux_vfs}"

for vfid in $dpdk_vfs $linux_vfs; do
    vf_pci_id=$(readlink -ve "/sys/class/net/$1/device/virtfn$vfid") &&
    vf_pci_id=$(basename "$vf_pci_id") &&
    modalias=$(cat "/sys/class/net/$1/device/virtfn$vfid/modalias") &&
    def_driver=$(modprobe -R "$modalias") &&
    if echo "$dpdk_vfs" | grep -qw "$vfid" && \
            ! echo "$def_driver" | grep -q ^mlx; then
        driver=vfio-pci
    else
        driver="$def_driver"
    fi &&
    cur_drv=$(readlink "/sys/bus/pci/devices/$vf_pci_id/driver" 2>/dev/null) &&
    cur_drv=$(basename "$cur_drv")
    if ! [ "$cur_drv" = "$driver" ]; then
        driverctl --nosave set-override "$vf_pci_id" "$driver"
    fi
done
'''

ETHTOOL_SCRIPT = "{ethtool_cmd} {ethtool_opts}"

_OS_NET_CONFIG_MANAGED = "# os-net-config managed table"

_ROUTE_TABLE_DEFAULT = """# reserved values
#
255\tlocal
254\tmain
253\tdefault
0\tunspec
#
# local
#
#1\tinr.ruhep\n"""


IPV4_DEFAULT_GATEWAY_DESTINATION = "0.0.0.0/0"
IPV6_DEFAULT_GATEWAY_DESTINATION = "::/0"

POST_ACTIVATION = 'post-activation'
POST_DEACTIVATION = 'post-deactivation'
DISPATCH = 'dispatch'
CONFIG_RULES_FILE = '/var/lib/os-net-config/nmstate_files/rules.yaml'


def route_table_config_path():
    return "/etc/iproute2/rt_tables"


def _get_type_value(str_val):
    if isinstance(str_val, str):
        if str_val.isdigit():
            return int(str_val)
        if str_val.lower() in ['true', 'yes', 'on']:
            return True
        if str_val.lower() in ['false', 'no', 'off']:
            return False
    return str_val


def get_route_options(route_options, key):
    """Parse `route_options` and return the value corresponding to `key`

    :param route_options: A string that has the key value pair seperated
        by spaces
    :param key: The `key` for which the value is required
    :returns: the route_option value corresponding to the key
    """

    items = route_options.split(' ')
    iter_list = iter(items)
    for item in iter_list:
        if key in item:
            return _get_type_value(next(iter_list))
    return


def is_dict_subset(superset, subset):
    """Check to see if one dict is a subset of another dict.

    :param superset: The bigger config, typically the present state
    :param subset: The smaller config, typically the desired state
    :returns: A boolean indicating if the desired state is already
        configured
    """

    if superset == subset:
        return True
    if superset and subset:
        if DISPATCH in superset.keys() and \
            DISPATCH not in subset.keys():
            return False

        for key, value in subset.items():
            if key not in superset:
                # Items which are empty or false
                # shall be considered as absent
                if value:
                    return False
                else:
                    continue
            if isinstance(value, dict):
                if not is_dict_subset(superset[key], value):
                    return False
            elif isinstance(value, int):
                if value != superset[key]:
                    return False
            elif isinstance(value, str):
                if value != superset[key]:
                    return False
            elif isinstance(value, list):
                try:
                    if not set(value) <= set(superset[key]):
                        return False
                except TypeError:
                    for item in value:
                        if item not in superset[key]:
                            if isinstance(item, dict):
                                for s_items in superset[key]:
                                    if is_dict_subset(s_items, item):
                                        break
                                else:
                                    return False
                            else:
                                return False
            elif isinstance(value, set):
                if not value <= superset[key]:
                    return False
            else:
                if not value == superset[key]:
                    return False
        return True
    return False


def _add_sub_tree(data, subtree):
    """Create a nested dict with the keys mentioned in subtree

    :param data: Starting point for the creation of nested dict
    :param subtree: list of keys used in the creation of nested
        dict.
    :raises os_net_config.ConfigurationError: if the data is None
    :returns: The tip of the nested dict created
    """
    if data is None:
        msg = "Subtree can't be created on None Types"
        raise os_net_config.ConfigurationError(msg)
    config = data
    if subtree:
        for cfg in subtree:
            if cfg not in config:
                config[cfg] = {}
            config = config[cfg]
    return config


def parse_bonding_options(bond_options_str):
    """Parse the bonding actions for linux bond/ovs-bond

    :param bond_options_str: A string having the bond_options in
        space separated key value pair
    :returns: A dict of bond options
    """
    bond_options_dict = {}
    if bond_options_str:
        options = re.findall(r'(.+?)=(.+?)($|\s)', bond_options_str)
        for option in options:
            bond_options_dict[option[0]] = _get_type_value(option[1])
    return bond_options_dict


def set_linux_bonding_options(bond_options, primary_iface=None):
    """Parse the linux bond options from templates

    The linux_bond options are mapped to the nmstate schema

    :param bond_options: A dict of bond options
    :param primary_iface: Specify the primary interface of the bond
    :returns: The bond configuration in nmstate schema format
    """
    linux_bond_options = [
        "ad_actor_system", "ad_actor_sys_prio", "ad_select",
        "ad_user_port_key", "arp_ip_target", "arp_validate",
        "all_slaves_active", "arp_all_targets", "arp_interval",
        "downdelay", "updelay", "miimon", "lacp_rate",
        "fail_over_mac", "lp_interval", "packets_per_slave", "min_links",
        "primary", "primary_reselect", "resend_igmp", "tlb_dynamic_lb",
        "use_carrier", "num_grat_arp", "num_unsol_na", "xmit_hash_policy"
    ]
    bond_data = {Bond.MODE: BondMode.ACTIVE_BACKUP,
                 Bond.OPTIONS_SUBTREE: {},
                 Bond.PORT: []}
    bond_options_data = {}
    if 'mode' in bond_options:
        bond_data[Bond.MODE] = bond_options['mode']

    for options in linux_bond_options:
        if options in bond_options:
            bond_options_data[options] = bond_options[options]
    bond_data[Bond.OPTIONS_SUBTREE] = bond_options_data

    if primary_iface and bond_data[Bond.MODE] == BondMode.ACTIVE_BACKUP:
        bond_options_data['primary'] = primary_iface

    if len(bond_data[Bond.OPTIONS_SUBTREE]) == 0:
        del bond_data[Bond.OPTIONS_SUBTREE]
    return bond_data


def set_ovs_bonding_options(bond_options):
    """Parse the ovs bond options from templates

    The ovs_bond options are mapped to the nmstate schema

    :param bond_options: A dict of bond options
    :returns: The bond configuration in nmstate schema format
    """
    # Duplicate entries for other-config are added so as to avoid
    # the confusion around other-config vs other_config in ovs
    ovs_other_config = ["other_config:lacp-fallback-ab",
                        "other_config:lacp-time",
                        "other_config:bond-detect-mode",
                        "other_config:bond-miimon-interval",
                        "other_config:bond-rebalance-interval",
                        "other_config:bond-primary",
                        "other-config:lacp-fallback-ab",
                        "other-config:lacp-time",
                        "other-config:bond-detect-mode",
                        "other-config:bond-miimon-interval",
                        "other-config:bond-rebalance-interval",
                        "other-config:bond-primary"]
    other_config = {}
    bond_data = {OVSBridge.Port.LinkAggregation.MODE:
                 OVSBridge.Port.LinkAggregation.Mode.ACTIVE_BACKUP,
                 OVSBridge.PORT_SUBTREE:
                     [{OVSBridge.Port.LinkAggregation.PORT_SUBTREE: []}],
                 OvsDB.KEY: {OvsDB.OTHER_CONFIG: other_config}}

    if 'bond_mode' in bond_options:
        bond_data[OVSBridge.Port.LinkAggregation.MODE
                  ] = bond_options['bond_mode']
    elif 'lacp' in bond_options and bond_options['lacp'] == 'active':
        bond_data[OVSBridge.Port.LinkAggregation.MODE
                  ] = OVSBridge.Port.LinkAggregation.Mode.LACP

    if 'bond_updelay' in bond_options:
        bond_data[OVSBridge.Port.LinkAggregation.Options.UP_DELAY
                  ] = bond_options['bond_updelay']

    for options in ovs_other_config:
        if options in bond_options:
            other_config[options[len("other_config:"):]
                         ] = bond_options[options]
    return bond_data


def _is_any_ip_addr(address):
    if address.lower() == 'any' or address.lower() == 'all':
        return True
    return False


class NmstateNetConfig(os_net_config.NetConfig):
    """Configure network interfaces using NetworkManager via nmstate API."""

    def __init__(self, noop=False, root_dir=''):
        super(NmstateNetConfig, self).__init__(noop, root_dir)
        # Dict of the interface data, with key being the interface name
        self.interface_data = {}
        # Dict of the vlan data, with keys being the vlan name
        self.vlan_data = {}
        # Dict of the route data, with keys being the device name
        self.route_data = {}
        # List of the rules data
        self.rules_data = []
        self.dns_data = {'server': [], 'domain': []}
        # Dict of the ovs bridges, with keys being the device name
        self.bridge_data = {}
        # Dict of the linux bond data, with keys being the device name
        self.linuxbond_data = {}
        self.ovs_port_data = {}
        self.member_names = {}
        self.renamed_interfaces = {}
        self.bond_primary_ifaces = {}
        self.route_table_data = {}
        # SR-IOV PF configurations inline with nmstate schema
        # {pf1: pf1_config, pf2: pf2_config}
        self.sriov_pf_data = {}
        # SR-IOV VF configurations inline with nmstate schema
        # {pf1: [list of vf configs of pf1], pf2: [list of vf configs of pf2]}
        self.sriov_vf_data = {}
        # SR-IOV VF drivers that needs override.
        #  {pf1: {vfid1: driver, vfid2: driver},
        #   pf2: {vfid1: driver, vfid2: driver}}
        self.vf_drv_override = {}
        self.migration_enabled = False
        # Boolean flag to indicate that the PF ports are added
        # and needs configuration. The PF ports will be configured
        # separately if the flag is set.
        self.need_pf_config = False
        # Boolean flag to indicate that the VF ports are added
        # and needs configuration. The VF ports will be configured
        # separately if the flag is set. It will be applicable
        # only for NIC Partitioning use cases.
        self.need_vf_config = False
        self.initial_state = netinfo.show_running_config()
        self.__dump_key_config(
            self.initial_state, msg='Initial network settings'
        )
        logger.info('nmstate net config provider created.')

    def reload_nm(self):
        """Reload NetworkManager connections

        Perform a reload of all the NM connections so that the
        updates (if any) to the ifcfg-* files related to
        NM_CONTROLLED shall be re-applied.
        """
        cmd = ['nmcli', 'connection', 'reload']
        msg = "Reloading nmcli connections"
        self.execute(msg, *cmd)

    def rollback_to_initial_settings(self):
        """Rollback to the initial settings

        The nmstate apply rolls back to the previous state whenever
        it fails. But os-net-config applies the nmstate templates
        several times during the run and its possible that a certain
        template could have failed. In that case, the roll back
        provided by nmstate would be limited to the specific failure
        and as such the failure needs to be handled so that the
        initial settings is restored.
        """
        logger.info("Rolling back to initial settings.")
        cur_state = netinfo.show_running_config()
        diff_state = gen_diff.generate_differences(self.initial_state,
                                                   cur_state)
        msg = "Applying the difference to go back to initial settings "
        self.__dump_key_config(diff_state, msg=msg)
        netapplier.apply(diff_state, verify_change=True)

    def __dump_config(self, config, msg="Applying config"):
        cfg_dump = yaml.dump(config, default_flow_style=False,
                             allow_unicode=True, encoding=None)
        logger.debug("----------------------------")
        logger.debug("%s\n%s", msg, cfg_dump)

    def __dump_key_config(self, config, msg="Applying config"):
        cfg_dump = yaml.dump(config, default_flow_style=False,
                             allow_unicode=True, encoding=None)
        logger.info("----------------------------")
        logger.info("%s\n%s", msg, cfg_dump)

    def get_vf_config(self, sriov_vf):
        """Create the nmstate schema for the given VF

        The VF parameters are translated to nmstate schema.

        :param sriov_vf: The SriovVF object that has the VF config
        :returns: The VF config in nmstate schema format
        """
        vf_config = {}
        vf_config[Ethernet.SRIOV.VFS.ID] = sriov_vf.vfid
        if sriov_vf.macaddr:
            vf_config[Ethernet.SRIOV.VFS.MAC_ADDRESS] = sriov_vf.macaddr
        if sriov_vf.spoofcheck:
            if sriov_vf.spoofcheck == 'on':
                vf_config[Ethernet.SRIOV.VFS.SPOOF_CHECK] = True
            else:
                vf_config[Ethernet.SRIOV.VFS.SPOOF_CHECK] = False
        if sriov_vf.trust:
            if sriov_vf.trust == 'on':
                vf_config[Ethernet.SRIOV.VFS.TRUST] = True
            else:
                vf_config[Ethernet.SRIOV.VFS.TRUST] = False
        if sriov_vf.min_tx_rate:
            vf_config[Ethernet.SRIOV.VFS.MIN_TX_RATE] = sriov_vf.min_tx_rate
        if sriov_vf.max_tx_rate:
            vf_config[Ethernet.SRIOV.VFS.MAX_TX_RATE] = sriov_vf.max_tx_rate
        if sriov_vf.vlan_id:
            vf_config[Ethernet.SRIOV.VFS.VLAN_ID] = sriov_vf.vlan_id
            if sriov_vf.qos:
                vf_config[Ethernet.SRIOV.VFS.QOS] = sriov_vf.qos
        return vf_config

    def update_vf_config(self, sriov_vf):
        """Update the VF config data

        The VF config in objects.SriovVF format will be converted in to
        the nmstate schema format and updated in the provider's data struct.

        :param sriov_vf: VF data (objects.SriovVF) that shall be converted to
            nmstate schema and stored
        :raises objects.InvalidConfigException: when the PF is not yet
            configured, while attempting a VF configuration
        """
        if sriov_vf.device in self.sriov_vf_data:
            logger.info(
                "%s-%d: Updating VF, Trust: %s "
                "Spoofcheck: %s Vlan: %d Qos: %d "
                "Min Rate: %d Max Rate: %d",
                sriov_vf.device, sriov_vf.vfid,
                sriov_vf.trust, sriov_vf.spoofcheck,
                sriov_vf.vlan_id, sriov_vf.qos,
                sriov_vf.min_tx_rate, sriov_vf.max_tx_rate
            )
            vf_config = self.get_vf_config(sriov_vf)
            self.sriov_vf_data[sriov_vf.device][sriov_vf.vfid] = vf_config
            self.add_vf_driver_override(sriov_vf)
        else:
            msg = f"{sriov_vf.device}-{sriov_vf.vfid}: PF is not configured"
            raise objects.InvalidConfigException(msg)

    def apply_pf_config(self, activate):
        """Apply the PF Configuration for all the required interfaces

            The required nmstate schema based configurations are available in
            `sriov_pf_data`. The generated nmstate schema is applied
            sequentially for one device after the other. These PF
            configurations are compared against the current state of those
            interfaces. If there is a mismatch in the current state and
            desired state, only then the generated nmstate templates is applied

        :param activate: A boolean which indicates if the config should
            be activated by applying the desired state.
        :returns: The list of devices configured
        """
        updated_pfs = []
        # The desired state of the PF's are applied one after the
        # other, so as to avoid driver errors.
        for pf_name in self.sriov_pf_data.keys():
            pf_state = self.sriov_pf_data[pf_name]
            # FIXME: The comparison of the current state vs desired state needs
            # to be performed in nmstate.
            # JIRA: https://issues.redhat.com/browse/RHEL-67120
            cur_state = self.iface_state(pf_name)
            if not is_dict_subset(cur_state, pf_state):
                if not self.noop and activate:
                    logger.debug("%s: Applying the PF config", pf_name)
                    self.nmstate_apply(self.set_ifaces([pf_state]),
                                       verify=True)
                    updated_pfs.append(pf_name)
            else:
                logger.info("%s: No changes required for PF", pf_name)
        self.need_pf_config = False
        return updated_pfs

    def apply_vf_config(self, activate):
        """Apply the VF Configuration for all the required interfaces

            The required nmstate schema based VF configurations are available
            in `sriov_vf_data` and the PF configuration in `sriov_pf_data`.
            The generated nmstate schema is applied sequentially for one
            device after the other. These configurations are compared
            against the current state of those interfaces. If there is
            a mismatch in the current state and desired state, the nmstate
            templates are applied

        :param activate: A boolean which indicates if the config should
            be activated by applying the desired state.
        :raises ConfigurationError: when the PF is not yet
            configured, while attempting a VF configuration
        :returns: The list of devices configured
        """

        updated_pfs = []
        for pf in self.sriov_vf_data.keys():
            required_vfs = []
            pf_state = {}

            if pf in self.sriov_pf_data:
                pf_state = self.sriov_pf_data[pf]
            else:
                msg = f"{pf} not found"
                raise os_net_config.ConfigurationError(msg)

            linux_vfs = []
            dpdk_vfs = []
            # The VFs used in NIC Partitioning are configured
            for vf in self.sriov_vf_data[pf]:
                if vf:
                    required_vfs.append(vf)
                    vfid = vf[Ethernet.SRIOV.VFS.ID]
                    vf_driver = self.vf_drv_override[pf].get(vfid, None)
                    # The VF's that needs a driver override shall be added to
                    # dpdk_vfs. Other VFs shall be added to linux_vfs.
                    # When SR-IOV driver auto probe is disabled, these VFs
                    # will be bound with the corresponding linux drivers.
                    if vf_driver and vf_driver == 'vfio-pci':
                        dpdk_vfs.append(str(vfid))
                    else:
                        linux_vfs.append(str(vfid))

            if required_vfs:
                bind_script = _VF_BIND_DRV_SCRIPT.format(
                    dpdk_vfs=' '.join(dpdk_vfs),
                    linux_vfs=' '.join(linux_vfs))
                self.add_dispatch_script(pf_state, POST_ACTIVATION,
                                         bind_script)
                # Add the generated VF configuration
                pf_state[
                    Ethernet.CONFIG_SUBTREE][
                    Ethernet.SRIOV_SUBTREE][
                    Ethernet.SRIOV.VFS_SUBTREE] = required_vfs
                cur_state = self.iface_state(pf_state['name'])
                # compare the desired state with the current state
                # FIXME: The comparison of the desired state and current
                # state shall be managed by nmstate itself.
                # JIRA: https://issues.redhat.com/browse/RHEL-67120

                if not is_dict_subset(cur_state, pf_state):
                    if not self.noop and activate:
                        logger.debug(
                            "%s: Applying the VF parameters",
                            pf_state["name"],
                        )
                        self.nmstate_apply(self.set_ifaces([pf_state]),
                                           verify=True)
                        # NetworkManager-dispatcher scripts will bind the VFs
                        # with the drivers. Wait for the completion of the
                        # driver bindings.
                        if linux_vfs:
                            lnx_driver = common.get_default_vf_driver(
                                pf, linux_vfs[0]
                            )
                            common.wait_for_vf_driver_binding(
                                pf,
                                linux_vfs,
                                lnx_driver,
                            )
                        if dpdk_vfs:
                            common.wait_for_vf_driver_binding(
                                pf,
                                dpdk_vfs,
                                "vfio-pci",
                            )
                        updated_pfs.append(pf_state["name"])
                else:
                    logger.info(
                        "%s: No changes required for VFs", pf_state["name"]
                    )
        # Clear the flag once all the VFs are configured
        self.need_vf_config = False
        return updated_pfs

    def get_route_tables(self):
        """Generate configuration content for routing tables.

        This method first extracts the existing route table definitions. If
        any non-default tables exist, they will be kept unless they conflict
        with new tables defined in the route_tables dict.

        :returns route_tables: A dict of RouteTable objects
        """

        rt_tables = {}
        rt_config = common.get_file_data(route_table_config_path()).split('\n')
        for line in rt_config:
            # ignore comments and black lines
            line = line.strip()
            if not line or line.startswith('#'):
                pass
            else:
                id_name = line.split()
                if len(id_name) > 1 and id_name[0].isdigit():
                    rt_tables[id_name[1]] = int(id_name[0])
        self.__dump_config(rt_tables,
                           msg='Contents of /etc/iproute2/rt_tables')
        return rt_tables

    def generate_route_table_config(self, route_tables):
        """Generate configuration content for routing tables.

        This method first extracts the existing route table definitions. If
        any non-default tables exist, they will be kept unless they conflict
        with new tables defined in the route_tables dict.

        :param route_tables: A dict of RouteTable objects
        :raises ConfigurationError: when route table id/name conflicts with
            reserved ones
        :returns: The updated content for /etc/iproute2/rt_tables
        """

        custom_tables = {}
        res_ids = ['0', '253', '254', '255']
        res_names = ['unspec', 'default', 'main', 'local']
        rt_config = common.get_file_data(route_table_config_path()).split('\n')
        rt_defaults = _ROUTE_TABLE_DEFAULT.split("\n")
        data = _ROUTE_TABLE_DEFAULT
        for line in rt_config:
            line = line.strip()
            if line in rt_defaults:
                continue
            # Leave non-standard comments intact in file
            if line.startswith('#'):
                data += f"{line}\n"
            # Ignore old managed entries, will be added back if in new config.
            elif line.find(_OS_NET_CONFIG_MANAGED) == -1:
                id_name = line.split()
                # Keep custom tables if there is no conflict with new tables.
                if len(id_name) > 1 and id_name[0].isdigit():
                    if not id_name[0] in res_ids:
                        if not id_name[1] in res_names:
                            if not int(id_name[0]) in route_tables:
                                if not id_name[1] in route_tables.values():
                                    # Replicate line with any comments appended
                                    custom_tables[id_name[0]] = id_name[1]
                                    data += f"{line}\n"
        if custom_tables:
            logger.debug("Present state of route tables: %s", custom_tables)
        for id in sorted(route_tables):
            if str(id) in res_ids:
                message = (
                    f"Table {route_tables[id]}({id}) conflicts with "
                    f"reserved table "
                    f"{res_names[res_ids.index(str(id))]}({id})"
                )
                raise os_net_config.ConfigurationError(message)
            elif route_tables[id] in res_names:
                message = (
                    f"Table {route_tables[id]}({id}) conflicts with "
                    f"reserved table {route_tables[id]}"
                    f"({res_ids[res_names.index(route_tables[id])]})"
                )
                raise os_net_config.ConfigurationError(message)
            else:
                data += f"{id}\t{route_tables[id]}     "\
                        f"{_OS_NET_CONFIG_MANAGED}\n"
        return data

    def iface_state(self, name=''):
        """Return the current interface state according to nmstate.

        Return the current state of all interfaces, or the named interface.
        :param name: name of the interface to return state, otherwise all.
        :returns: list state of all interfaces when name is not specified, or
                  the state of the specific interface when name is specified
        """
        ifaces = netinfo.show_running_config()[Interface.KEY]
        if name != '':
            for iface in ifaces:
                if iface[Interface.NAME] != name:
                    continue
                self.__dump_config(iface, msg=f"{name}: Present state")
                return iface
        else:
            self.__dump_config(ifaces, msg="Present state for all interfaces")
            return ifaces

    def cleanup_all_ifaces(self, exclude_nics=[]):
        """Cleanup all the interfaces that are available

        Removes all the interfaces that are available to be configured
        by nmstate. The nics marked in `exclude_nics` shall not be removed

        :param exclude_nics: The list of nics that shall not be removed
        """

        logger.info("cleaning up all network configs...")
        exclude_nics.extend(['lo'])
        exclude_nics.extend(common.get_sriov_pf_names())
        exclude_nics.extend(common.get_dpdk_iface_names())
        exclude_types = [OVSBridge.TYPE, OVSInterface.TYPE]
        ifaces = netinfo.show_running_config()[Interface.KEY]
        logger.debug("Interface name excluded: %s", ", ".join(exclude_nics))
        logger.debug("Interface type excluded: %s", ", ".join(exclude_types))
        for iface in ifaces:
            if iface.get(Interface.NAME) in exclude_nics:
                logger.info(
                    "%s: Interface name is excluded from cleanup",
                    iface[Interface.NAME]
                )
            elif common.is_vf_by_name(iface.get(Interface.NAME)):
                logger.info(
                    "%s: VFs are excluded from cleanup",
                    iface[Interface.NAME]
                )
            elif iface[Interface.STATE] == InterfaceState.IGNORE:
                logger.info(
                    "%s: Interface state is excluded from cleanup",
                    iface[Interface.NAME]
                )
            elif iface.get(Interface.TYPE) in exclude_types:
                logger.info(
                    "%s: Interface type %s is excluded from cleanup",
                    iface[Interface.NAME],
                    iface.get(Interface.TYPE)
                )
            else:
                clean_iface = {
                    Interface.NAME: iface.get(Interface.NAME),
                    Interface.STATE: InterfaceState.ABSENT,
                    Interface.TYPE: iface.get(Interface.TYPE),
                }
                state = {Interface.KEY: [clean_iface]}
                self.__dump_key_config(
                    clean_iface, msg=f"{iface[Interface.NAME]}: Cleaning up"
                )
                if not self.noop:
                    netapplier.apply(state, verify_change=True)

    def route_state(self, name=''):
        """Return the current routes set according to nmstate.

        Return the current routes for all interfaces, or the named interface.
        :param name: name of the interface to return state, otherwise all.
        :returns: list of all interfaces, or those matching name if specified
        """

        routes = netinfo.show_running_config()[
            NMRoute.KEY][NMRoute.CONFIG]
        if name != "":
            route = list(x for x in routes if x[
                NMRoute.NEXT_HOP_INTERFACE] == name)
            if self.noop:
                self.__dump_config(route, msg=f"{name}: Present route config")
            return route
        else:
            if self.noop:
                self.__dump_config(routes, msg="Present route config")
            return routes

    def rule_state(self):
        """Return the current rules set according to nmstate.

        Return the current ip rules for all interfaces, or the named interface.
        :param name: name of the interface to return state, otherwise all.
        :returns: list of all interfaces, or those matching name if specified
        """

        rules = netinfo.show_running_config()[
            NMRouteRule.KEY][NMRouteRule.CONFIG]
        if self.noop:
            self.__dump_config(rules, msg="Present IP Rules")
        return rules

    def set_ifaces(self, iface_data):
        """Prepare the nmstate schema for the interfaces.

        :param iface_data: interface config json
        :return Interface state
        """
        state = {Interface.KEY: iface_data}
        if self.noop:
            self.__dump_config(state, msg="Prepared interface config")
        return state

    def set_dns(self):
        """Prepare the nmstate schema for DNS

        :param dns_data:  config json
        :return dns config
        """
        state = {DNS.KEY: {DNS.CONFIG: {DNS.SERVER: self.dns_data['server'],
                                        DNS.SEARCH: self.dns_data['domain']}}}
        if self.noop:
            self.__dump_config(state, msg="Prepared DNS")
        return state

    def set_routes(self, route_data):
        """Prepare the nmstate schema for routes

        :param route_data: list of routes
        :return route states
        """

        state = {NMRoute.KEY: {NMRoute.CONFIG: route_data}}
        if self.noop:
            self.__dump_config(state, msg="Prepared routes")
        return state

    def set_rules(self, rule_data):
        """Prepare the nmstate schema for rules

        :param rule_data: list of rules
        :return route rule states
        """
        state = {NMRouteRule.KEY: {NMRouteRule.CONFIG: rule_data}}
        if self.noop:
            self.__dump_config(state, msg="Prepared rules are")
        return state

    def nmstate_apply(self, new_state, verify=True):
        """Apply the desired rules using nmstate.

        :param new_state: desired network config json
        :param verify: boolean that determines if config will be verified
        """
        self.__dump_key_config(
            new_state, msg="Applying the config with nmstate"
        )
        if not self.noop:
            try:
                netapplier.apply(new_state, verify_change=verify)
            except error.NmstateVerificationError as exc:
                logger.error("**** Verification Error *****")
                logger.error(
                    "Error seen while applying the nmstate templates %s",
                    exc,
                )
                self.errors.append(exc)
            except error.NmstateError as exc:
                logger.error(
                    "Error seen while applying the nmstate templates %s",
                    exc,
                )
                self.errors.append(exc)

    def generate_routes(self, interface_name):
        """Generate the route configurations required. Add/Remove routes

        :param interface_name: interface name for which routes are required
        :return: tuple having list of routes to be added and deleted
        """
        add_routes = self.route_data.get(interface_name, [])
        curr_routes = self.route_state(interface_name)

        del_routes = []
        clean_routes = False
        self.__dump_config(
            curr_routes, msg=f"{interface_name}: Present route config"
        )
        self.__dump_config(
            add_routes, msg=f"{interface_name}: Desired route config"
        )

        for c_route in curr_routes:
            if c_route not in add_routes:
                clean_routes = True
                break
        if clean_routes:
            for c_route in curr_routes:
                c_route[NMRoute.STATE] = NMRoute.STATE_ABSENT
                del_routes.append(c_route)
                logger.info("Prepare to remove route - %s", c_route)
        return add_routes, del_routes

    def _is_managed_iprules(self, c_rule):
        """check if ip rule is manage by os-net.

        :param c_rule: current defined rule
        """

        if os.path.exists(CONFIG_RULES_FILE):
            mng_iprules = yaml.safe_load(
                common.get_file_data(CONFIG_RULES_FILE))
            filtered_c_rule = {
                key: value for key, value in c_rule.items()
                if key not in ['family', 'priority']
            }
            for iprule in mng_iprules['route-rules']['config']:
                if filtered_c_rule == iprule:
                    return True
            return False
        else:
            return False

    def generate_rules(self):
        """Generate the rule configurations required. Add/Remove rules

        :return: tuple having list of rules to be added and deleted
        """
        add_rules = self.rules_data
        curr_rules = self.rule_state()
        del_rules = []
        clear_rules = False

        self.__dump_config(curr_rules, msg="Present set of ip rules")

        self.__dump_config(add_rules, msg="Desired ip rules")

        for c_rule in curr_rules:
            if c_rule not in add_rules:
                clear_rules = True
                break
        if clear_rules:
            for c_rule in curr_rules:
                if self._is_managed_iprules(c_rule):
                    c_rule[NMRouteRule.STATE] = NMRouteRule.STATE_ABSENT
                    del_rules.append(c_rule)
                    logger.info("Prepare to remove rule - %s", c_rule)
        return add_rules, del_rules

    def interface_mac(self, iface):
        """Get the interface's mac address

        :param iface: name of the interface for which mac address is required
        """
        iface_data = self.iface_state(iface)
        if iface_data and Interface.MAC in iface_data:
            return iface_data[Interface.MAC]

    def get_ovs_ports(self, members):
        """Get the ovs ports in nmstate schema format

        :param members: The members of the ovs/ovs-user bridges
        :returns: The Bridge ports in nmstate schema
        """
        bps = []
        for member in members:
            if member.startswith('vlan'):
                vlan_id = int(member.strip('vlan'))
                port = {
                    OVSBridge.Port.NAME: member,
                    OVSBridge.Port.VLAN_SUBTREE: {
                        OVSBridge.Port.Vlan.MODE: 'access',
                        OVSBridge.Port.Vlan.TAG: vlan_id
                    }
                }
                bps.append(port)
            # if the member is of type interface but a vlan
            # like eth0.605
            elif re.match(r'\w+\.\d+$', member):
                vlan_id = int(member.split('.')[1])
                port = {
                    OVSBridge.Port.NAME: member,
                    OVSBridge.Port.VLAN_SUBTREE: {
                        OVSBridge.Port.Vlan.MODE: 'access',
                        OVSBridge.Port.Vlan.TAG: vlan_id
                    }
                }
                bps.append(port)
            else:
                port = {'name': member}
                bps.append(port)
        return bps

    def add_ethtool_subtree(self, data, sub_config, command):
        """Store the Ethtool options in nmstate schema format

        :raises ConfigurationError: Non supported ethtool options
        """

        config = _add_sub_tree(data, sub_config['sub-tree'])
        ethtool_map = sub_config['map']

        # skip first 2 entries as they are already validated
        for index in range(2, len(command) - 1, 2):
            value = _get_type_value(command[index + 1])
            if command[index] in ethtool_map.keys():
                config[ethtool_map[command[index]]] = value
            elif (sub_config['sub-options'] == 'copy'):
                config[command[index]] = value
            else:
                msg = (
                    f"Unhandled ethtool option {command[index]} for "
                    f"command {command}."
                )
                raise os_net_config.ConfigurationError(msg)

    def add_ethtool_config(self, iface_name, data, ethtool_options):
        """Add Ethtool configs in nmstate schema format

        :raises ConfigurationError: Non supported / Unhandled ethtool options
        """
        ethtool_generic_options = {'sub-tree': [Ethernet.CONFIG_SUBTREE],
                                   'sub-options': None,
                                   'map': {
                                   'speed': Ethernet.SPEED,
                                   'autoneg': Ethernet.AUTO_NEGOTIATION,
                                   'duplex': Ethernet.DUPLEX}
                                   }
        ethtool_set_ring = {'sub-tree': [Ethtool.CONFIG_SUBTREE,
                                         Ethtool.Ring.CONFIG_SUBTREE],
                            'sub-options': None,
                            'map': {
                            'rx': Ethtool.Ring.RX,
                            'tx': Ethtool.Ring.TX,
                            'rx-jumbo': Ethtool.Ring.RX_JUMBO,
                            'rx-mini': Ethtool.Ring.RX_MINI}
                            }
        ethtool_set_pause = {'sub-tree': [Ethtool.CONFIG_SUBTREE,
                                          Ethtool.Pause.CONFIG_SUBTREE],
                             'sub-options': None,
                             'map': {
                             'autoneg': Ethtool.Pause.AUTO_NEGOTIATION,
                             'tx': Ethtool.Pause.TX,
                             'rx': Ethtool.Pause.RX}
                             }
        coalesce_map = {'adaptive-rx': Ethtool.Coalesce.ADAPTIVE_RX,
                        'adaptive-tx': Ethtool.Coalesce.ADAPTIVE_TX,
                        'rx-usecs': Ethtool.Coalesce.RX_USECS,
                        'rx-frames': Ethtool.Coalesce.RX_FRAMES,
                        'rx-usecs-irq': Ethtool.Coalesce.RX_USECS_IRQ,
                        'rx-frames-irq': Ethtool.Coalesce.RX_FRAMES_IRQ,
                        'tx-usecs': Ethtool.Coalesce.TX_USECS,
                        'tx-frames': Ethtool.Coalesce.TX_FRAMES,
                        'tx-usecs-irq': Ethtool.Coalesce.TX_USECS_IRQ,
                        'tx-frames-irq': Ethtool.Coalesce.TX_FRAMES_IRQ,
                        'stats-block-usecs':
                            Ethtool.Coalesce.STATS_BLOCK_USECS,
                        'pkt-rate-low': Ethtool.Coalesce.PKT_RATE_LOW,
                        'rx-usecs-low': Ethtool.Coalesce.RX_USECS_LOW,
                        'rx-frames-low': Ethtool.Coalesce.RX_FRAMES_LOW,
                        'tx-usecs-low': Ethtool.Coalesce.TX_USECS_LOW,
                        'tx-frames-low': Ethtool.Coalesce.TX_FRAMES_LOW,
                        'pkt-rate-high': Ethtool.Coalesce.PKT_RATE_HIGH,
                        'rx-usecs-high': Ethtool.Coalesce.RX_USECS_HIGH,
                        'rx-frames-high': Ethtool.Coalesce.RX_FRAMES_HIGH,
                        'tx-usecs-high': Ethtool.Coalesce.TX_USECS_HIGH,
                        'tx-frames-high': Ethtool.Coalesce.TX_FRAMES_HIGH,
                        'sample-interval': Ethtool.Coalesce.SAMPLE_INTERVAL}
        ethtool_set_coalesce = {'sub-tree': [Ethtool.CONFIG_SUBTREE,
                                             Ethtool.Coalesce.CONFIG_SUBTREE],
                                'sub-options': None,
                                'map': coalesce_map
                                }
        ethtool_set_features = {'sub-tree': [Ethtool.CONFIG_SUBTREE,
                                             Ethtool.Feature.CONFIG_SUBTREE],
                                'sub-options': 'copy',
                                'map': {}}
        ethtool_map = {'-G': ethtool_set_ring,
                       '--set-ring': ethtool_set_ring,
                       '-A': ethtool_set_pause,
                       '--pause': ethtool_set_pause,
                       '-C': ethtool_set_coalesce,
                       '--coalesce': ethtool_set_coalesce,
                       '-K': ethtool_set_features,
                       '--features': ethtool_set_features,
                       '--offload': ethtool_set_features,
                       '-s': ethtool_generic_options,
                       '--change': ethtool_generic_options}
        if Ethernet.CONFIG_SUBTREE not in data:
            data[Ethernet.CONFIG_SUBTREE] = {}
        if Ethtool.CONFIG_SUBTREE not in data:
            data[Ethtool.CONFIG_SUBTREE] = {}

        for ethtool_opts in ethtool_options.split(';'):
            ethtool_opts = ethtool_opts.strip()
            if re.match(r'^(-[\S-]+[ ]+[\S]+)([ ]+[\S-]+[ ]+[\S]+)+',
                        ethtool_opts):
                # The regex pattern is strict and hence a minimum of 4 items
                # are present in ethtool_opts.
                command = ethtool_opts.split()
                if len(command) < 4:
                    msg = (
                        f"{iface_name}: Ethtool options {command} "
                        "is incomplete"
                    )
                    raise os_net_config.ConfigurationError(msg)

                option = command[0]
                accepted_dev_names = ['${DEVICE}', '$DEVICE', iface_name]
                if command[1] not in accepted_dev_names:
                    msg = (
                        f"{iface_name}: Incorrect dev name found in "
                        f"{ethtool_opts}"
                    )
                    raise os_net_config.ConfigurationError(msg)
                if option in ethtool_map.keys():
                    self.add_ethtool_subtree(data, ethtool_map[option],
                                             command)
                else:
                    opts = " ".join(command[2:])
                    ethtool_script = ETHTOOL_SCRIPT.format(
                        ethtool_opts=f"{option} $1 {opts}",
                        ethtool_cmd=utils.ethtool_path()
                        )
                    self.add_dispatch_script(
                        data, POST_ACTIVATION, ethtool_script
                        )

            else:
                command_str = '-s ${DEVICE} ' + ethtool_opts
                command = command_str.split()
                option = command[0]
                self.add_ethtool_subtree(data, ethtool_map[option], command)

    def _clean_iface(self, name, obj_type):
        """Removes the NetrworkManager device coniguration"""
        iface_data = {Interface.NAME: name,
                      Interface.TYPE: obj_type,
                      Interface.STATE: InterfaceState.ABSENT}
        absent_state_config = {Interface.KEY: [iface_data]}
        self.__dump_key_config(absent_state_config, msg=f"{name}: Cleaning")
        netapplier.apply(absent_state_config, verify_change=True)

    def enable_migration(self):
        """Enable migration from other providers to nmstate"""
        self.reload_nm()
        self.migration_enabled = True
        logger.info("nmstate: Migration is enabled.")

    def _add_common(self, base_opt):
        """Add common atrributes of the interface

        Add the common attributes of networks like IPv4, IPv6 addresses,
        routes, rules, DNS, MTU

        :param base_opt: The network object that has the device configs
            defined in the form objects._BaseOpts
        """
        data = {Interface.IPV4: {InterfaceIPv4.ENABLED: False},
                Interface.IPV6: {InterfaceIPv6.ENABLED: False},
                Interface.NAME: base_opt.name}
        if base_opt.use_dhcp:
            data[Interface.IPV4][InterfaceIPv4.ENABLED] = True
            data[Interface.IPV4][InterfaceIPv4.DHCP] = True
            data[Interface.IPV4][InterfaceIPv4.AUTO_DNS] = True
            data[Interface.IPV4][InterfaceIPv4.AUTO_ROUTES] = True
            data[Interface.IPV4][InterfaceIPv4.AUTO_GATEWAY] = True
        else:
            data[Interface.IPV4][InterfaceIPv4.DHCP] = False
            if base_opt.dns_servers:
                data[Interface.IPV4][InterfaceIPv4.AUTO_DNS] = False

        if base_opt.use_dhcpv6:
            data[Interface.IPV6][InterfaceIPv6.ENABLED] = True
            data[Interface.IPV6][InterfaceIPv6.DHCP] = True
            data[Interface.IPV6][InterfaceIPv6.AUTO_DNS] = True
            data[Interface.IPV6][InterfaceIPv6.AUTOCONF] = True
            data[Interface.IPV6][InterfaceIPv6.AUTO_DNS] = True
            data[Interface.IPV6][InterfaceIPv6.AUTO_ROUTES] = True
            data[Interface.IPV6][InterfaceIPv6.AUTO_GATEWAY] = True
        else:
            data[Interface.IPV6][InterfaceIPv6.DHCP] = False
            data[Interface.IPV6][InterfaceIPv6.AUTOCONF] = False
            if base_opt.dns_servers:
                data[Interface.IPV6][InterfaceIPv6.AUTO_DNS] = False

        if not base_opt.defroute:
            data[Interface.IPV4][InterfaceIPv4.AUTO_GATEWAY] = False
            data[Interface.IPV6][InterfaceIPv6.AUTO_GATEWAY] = False

        # NetworkManager always starts on boot, so set enabled state instead
        if base_opt.onboot:
            data[Interface.STATE] = InterfaceState.UP
        else:
            data[Interface.STATE] = InterfaceState.DOWN

        if not base_opt.nm_controlled:
            logger.info('Using NetworkManager, nm_controlled is always true.'
                        'Deprecating it from next release')
        if isinstance(base_opt, objects.Interface):
            if not base_opt.hotplug:
                logger.info('Using NetworkManager, hotplug is always set to'
                            'true. Deprecating it from next release')
        if base_opt.mtu:
            data[Interface.MTU] = base_opt.mtu
        if base_opt.addresses:
            v4_addresses = base_opt.v4_addresses()
            if v4_addresses:
                for address in v4_addresses:
                    netmask_ip = netaddr.IPAddress(address.netmask)
                    ip_netmask = {'ip': address.ip,
                                  'prefix-length': netmask_ip.netmask_bits()}
                    if InterfaceIPv4.ADDRESS not in data[Interface.IPV4]:
                        data[Interface.IPV4][InterfaceIPv4.ADDRESS] = []
                    data[Interface.IPV4][InterfaceIPv4.ENABLED] = True
                    data[Interface.IPV4][InterfaceIPv4.ADDRESS].append(
                        ip_netmask)

            v6_addresses = base_opt.v6_addresses()
            if v6_addresses:
                for v6_address in v6_addresses:
                    netmask_ip = netaddr.IPAddress(v6_address.netmask)
                    v6ip_netmask = {'ip': v6_address.ip,
                                    'prefix-length':
                                        netmask_ip.netmask_bits()}
                    if InterfaceIPv6.ADDRESS not in data[Interface.IPV6]:
                        data[Interface.IPV6][InterfaceIPv6.ADDRESS] = []
                    data[Interface.IPV6][InterfaceIPv6.ENABLED] = True
                    data[Interface.IPV6][InterfaceIPv6.ADDRESS].append(
                        v6ip_netmask)

        if base_opt.dhclient_args:
            msg = "DHCP Client args not supported in impl_nmstate, ignoring"
            logger.error(msg)
        if hasattr(base_opt, 'members'):
            for member in base_opt.members:
                if isinstance(member, objects.SriovVF):
                    self.update_vf_config(member)
        if base_opt.dns_servers:
            self._add_dns_servers(base_opt.dns_servers)
        if base_opt.domain:
            self._add_dns_domain(base_opt.domain)
        if base_opt.routes:
            self._add_routes(base_opt.name, base_opt.routes)
        if base_opt.rules:
            self._add_rules(base_opt.name, base_opt.rules)
        return data

    def _add_routes(self, interface_name, routes=[]):
        """Adds the routes in nmstate schema format

        :param interface_name: the name of the interface
        :param routes: A list of routes that needs to be added
        """

        routes_data = []
        logger.info("%s: adding custom route", interface_name)
        for route in routes:
            route_data = {}
            if route.route_options:
                value = get_route_options(route.route_options, 'metric')
                if value:
                    route.metric = value
                value = get_route_options(route.route_options, 'table')
                if value:
                    route.route_table = value
            if route.metric:
                route_data[NMRoute.METRIC] = route.metric
            if route.ip_netmask:
                route_data[NMRoute.DESTINATION] = route.ip_netmask
            if route.next_hop:
                if route.next_hop == "self":
                    route_data[NMRoute.NEXT_HOP_INTERFACE] = interface_name
                else:
                    route_data[NMRoute.NEXT_HOP_ADDRESS] = route.next_hop
                    route_data[NMRoute.NEXT_HOP_INTERFACE] = interface_name
                if route.default:
                    if route.next_hop == "self":
                        msg = "self as next_hop allowed only with ip_netmask"
                        raise os_net_config.ConfigurationError(msg)
                    if ":" in route.next_hop:
                        route_data[NMRoute.DESTINATION] = \
                            IPV6_DEFAULT_GATEWAY_DESTINATION
                    else:
                        route_data[NMRoute.DESTINATION] = \
                            IPV4_DEFAULT_GATEWAY_DESTINATION
            rt_tables = self.get_route_tables()
            if route.route_table:
                if str(route.route_table).isdigit():
                    route_data[NMRoute.TABLE_ID] = route.route_table
                elif route.route_table in rt_tables:
                    route_data[NMRoute.TABLE_ID] = \
                        rt_tables[route.route_table]
                else:
                    logger.error(
                        "%s: Unidentified mapping for route_table %s",
                        interface_name,
                        route.route_table,
                    )

            routes_data.append(route_data)

        self.route_data[interface_name] = routes_data
        self.__dump_config(
            routes_data, msg=f"{interface_name}: Prepared route config"
        )

    def add_route_table(self, route_table):
        """Add a RouteTable object to the net config object.

        :param route_table: the RouteTable object to add.
        """
        logger.info(
            "ROUTE: adding route table: %s %s",
            route_table.name,
            route_table.table_id,
        )
        self.route_table_data[int(route_table.table_id)] = route_table.name
        location = route_table_config_path()
        data = self.generate_route_table_config(self.route_table_data)
        self.write_config(location, data)

    def rules_table_value_parse(self, table_id):
        rt_tables = self.get_route_tables()
        if table_id:
            if str(table_id).isdigit():
                return table_id
            elif table_id in rt_tables:
                return rt_tables[table_id]
            else:
                logger.error(
                    "IP-RULES: Unidentified mapping for table_id %s", table_id
                )

    def _parse_ip_rules(self, rule):
        """Parse IP rule commands

        The Ip rule commands are translated to nmstate schema

        :params rule: The IP rule that will be translated
        :raises ConfigurationError: Incomplete/Unhandled ip rule command
        """

        nm_rule_map = {
            'blackhole': {'nm_key': NMRouteRule.ACTION,
                          'nm_value': NMRouteRule.ACTION_BLACKHOLE},
            'unreachable': {'nm_key': NMRouteRule.ACTION,
                            'nm_value': NMRouteRule.ACTION_UNREACHABLE},
            'prohibit': {'nm_key': NMRouteRule.ACTION,
                         'nm_value': NMRouteRule.ACTION_PROHIBIT},
            'fwmark': {'nm_key': NMRouteRule.FWMARK, 'nm_value': None},
            'fwmask': {'nm_key': NMRouteRule.FWMASK, 'nm_value': None},
            'iif': {'nm_key': NMRouteRule.IIF, 'nm_value': None},
            'from': {'nm_key': NMRouteRule.IP_FROM, 'nm_value': None},
            'to': {'nm_key': NMRouteRule.IP_TO, 'nm_value': None},
            'priority': {'nm_key': NMRouteRule.PRIORITY, 'nm_value': None},
            'table': {'nm_key': NMRouteRule.ROUTE_TABLE, 'nm_value': None,
                      'nm_parse_value': self.rules_table_value_parse}}
        logger.debug("IP-RULES: Parsing Rule: %s", rule)
        items = rule.split()
        keyword = items[0]
        parse_start_index = 1
        rule_config = {}
        if keyword == 'del':
            rule_config[NMRouteRule.STATE] = NMRouteRule.STATE_ABSENT
        elif keyword in nm_rule_map.keys():
            parse_start_index = 0
        elif keyword != 'add':
            msg = f"IP-RULES: unhandled command: {rule}"
            raise os_net_config.ConfigurationError(msg)

        items_iter = iter(items[parse_start_index:])

        parse_complete = True
        while True:
            try:
                parse_complete = True
                item = next(items_iter)
                if item in nm_rule_map.keys():
                    value = _get_type_value(nm_rule_map[item]['nm_value'])
                    if not value:
                        parse_complete = False
                        value = _get_type_value(next(items_iter))
                        if 'nm_parse_value' in nm_rule_map[item]:
                            value = nm_rule_map[item]['nm_parse_value'](value)
                    rule_config[nm_rule_map[item]['nm_key']] = value
                else:
                    msg = f"IP-RULES: unhandled command: {rule}"
                    raise os_net_config.ConfigurationError(msg)
            except StopIteration:
                if not parse_complete:
                    msg = f"IP-RULES: incomplete command: {rule}"
                    raise os_net_config.ConfigurationError(msg)
                break

        # Just remove the from/to address when its all/any
        # the address defaults to all/any.
        if NMRouteRule.IP_FROM in rule_config:
            if _is_any_ip_addr(rule_config[NMRouteRule.IP_FROM]):
                del rule_config[NMRouteRule.IP_FROM]
        if NMRouteRule.IP_TO in rule_config:
            if _is_any_ip_addr(rule_config[NMRouteRule.IP_TO]):
                del rule_config[NMRouteRule.IP_TO]

        # TODO(Karthik) Add support for ipv6 rules as well
        # When neither IP_FROM nor IP_TO is set, specify the IP family
        if (NMRouteRule.IP_FROM not in rule_config.keys() and
                NMRouteRule.IP_TO not in rule_config.keys()):
            rule_config[NMRouteRule.FAMILY] = NMRouteRule.FAMILY_IPV4

        if NMRouteRule.PRIORITY not in rule_config.keys():
            logger.warning(
                "The ip rule %s doesn't have the priority set."
                "Its advisable to configure the priorities in "
                "order to have a deterministic behaviour",
                rule,
            )

        return rule_config

    def _add_rules(self, interface_name, rules=[]):
        """Add ip rules in nmstate schema format

        :param interface_name: Name of the interface for which the rules are
            required.
        :param rules: Rules required for the device (objects.RouteRule)
        """
        for rule in rules:
            rule_nm = self._parse_ip_rules(rule.rule)
            self.rules_data.append(rule_nm)

        logger.debug("%s: rule data\n%s", interface_name, self.rules_data)

    def _add_dns_servers(self, dns_servers):
        """Add dns servers in nmstate schema format

        :param dns_servers: A list of DNS servers
        """
        for dns_server in dns_servers:
            if dns_server not in self.dns_data['server']:
                logger.debug("DNS: Adding DNS server %s", dns_server)
                self.dns_data['server'].append(dns_server)

    def _add_dns_domain(self, dns_domain):
        """Add dns domain in nmstate schema format

        :param dns_domain: A list of DNS domains
        """
        if isinstance(dns_domain, str):
            logger.debug("DNS: Adding DNS domain %s", dns_domain)
            self.dns_data['domain'].extend([dns_domain])
            return

        for domain in dns_domain:
            if domain not in self.dns_data['domain']:
                logger.debug("DNS: Adding DNS domain %s", domain)
                self.dns_data['domain'].append(domain)

    def add_dispatch_script(self, device_data, stage, cmd):
        """Add the dispatch script for device

        :param device_data: The device data in nmstate schema format
        :param stage: nmstate supports 2 stages for running the
            dispatcher scripts. They are post-activation and post-deactivation.
        :param cmd: The dispatcher script that needs to be run on the
            desired stage for the device.
        """
        if DISPATCH not in device_data:
            device_data[DISPATCH] = {}
        if device_data[DISPATCH].get(stage, "") == "":
            device_data[DISPATCH][stage] = DISPATCHER_SCRIPT_PREFIX
        device_data[DISPATCH][stage] += f'{cmd}\n'

    def remove_empty_dispatch_scripts(self, cur_state, new_state):
        """Remove the dispatch scripts file when not required

        When the new state does not require dispatch scripts but the current
        state has the script file defined, the nmstate templates for removing
        the dispatcher shall be
        dispatch:
            post-activation: ""
            post-deactivation: ""
        """
        if cur_state and DISPATCH in cur_state.keys():
            if DISPATCH in new_state.keys():
                if POST_ACTIVATION not in new_state[DISPATCH].keys():
                    new_state[DISPATCH][POST_ACTIVATION] = ""
                if POST_DEACTIVATION not in new_state[DISPATCH].keys():
                    new_state[DISPATCH][POST_DEACTIVATION] = ""
            else:
                new_state[DISPATCH] = {POST_ACTIVATION: "",
                                       POST_DEACTIVATION: ""}

    def add_vf_driver_override(self, vf):
        """Add driver override for VFs

        The VF needs an explicit driver binding when sriov_drivers_autoprobe
        is disabled or the VF is attached to DPDK. The driver override
        shall be added here.

        :param vf: The VF device for which the driver override is required
        """
        if vf.driver:
            self.vf_drv_override[vf.device][vf.vfid] = vf.driver

    def add_interface(self, interface):
        """Add an Interface object to the net config object.

        :param interface: The Interface object to add.
        """
        if re.match(r'\w+\.\d+$', interface.name):
            vlan_id = int(interface.name.split('.')[1])
            device = interface.name.split('.')[0]
            vlan_port = objects.Vlan(
                device, vlan_id,
                use_dhcp=interface.use_dhcp, use_dhcpv6=interface.use_dhcpv6,
                addresses=interface.addresses, routes=interface.routes,
                rules=interface.rules, mtu=interface.mtu,
                primary=interface.primary, nic_mapping=None,
                persist_mapping=None, defroute=interface.defroute,
                dhclient_args=interface.dhclient_args,
                dns_servers=interface.dns_servers, nm_controlled=True,
                onboot=interface.onboot, domain=interface.domain)
            vlan_port.name = interface.name
            self.add_vlan(vlan_port)
            return

        if self.migration_enabled:
            self._clean_iface(interface.name, InterfaceType.ETHERNET)
        logger.info("%s: adding interface", interface.name)
        data = self._add_common(interface)

        data[Interface.TYPE] = InterfaceType.ETHERNET
        data[Ethernet.CONFIG_SUBTREE] = {}
        int_data = self.iface_state(interface.name)
        try:
            cur_numvfs = int_data['ethernet']['sr-iov']['total-vfs']
        except (KeyError, TypeError):
            cur_numvfs = 0
        if utils.get_totalvfs(interface.name) > 0:
            data[Ethernet.CONFIG_SUBTREE][Ethernet.SRIOV_SUBTREE] = {
                Ethernet.SRIOV.TOTAL_VFS: cur_numvfs}

        if interface.ethtool_opts:
            self.add_ethtool_config(interface.name, data,
                                    interface.ethtool_opts)

        if interface.renamed:
            logger.info(
                "%s: renamed from %s", interface.name, interface.hwname
            )
            self.renamed_interfaces[interface.hwname] = interface.name
        if interface.hwaddr:
            data[Interface.MAC] = interface.hwaddr

        self.__dump_key_config(data, msg=f"{interface.name}: Prepared config")
        self.interface_data[interface.name] = data

    def add_vlan(self, vlan):
        """Add a Vlan object to the net config object.

        :param vlan: The vlan object to add.
        """
        if self.migration_enabled:
            if vlan.bridge_name:
                self._clean_iface(vlan.name, InterfaceType.OVS_INTERFACE)
            else:
                self._clean_iface(vlan.name, InterfaceType.VLAN)
        logger.info("%s: adding vlan", vlan.name)

        data = self._add_common(vlan)
        if vlan.device:
            base_iface = vlan.device
        elif vlan.linux_bond_name:
            base_iface = vlan.linux_bond_name

        if vlan.bridge_name:
            # Handle the VLANs for ovs bridges
            # vlans on OVS bridges are internal ports (no device, etc)
            data[Interface.TYPE] = InterfaceType.OVS_INTERFACE
        else:
            data[Interface.TYPE] = InterfaceType.VLAN
            data[VLAN.CONFIG_SUBTREE] = {}
            data[VLAN.CONFIG_SUBTREE][VLAN.ID] = vlan.vlan_id
            data[VLAN.CONFIG_SUBTREE][VLAN.BASE_IFACE] = base_iface

        self.vlan_data[vlan.name] = data
        self.__dump_key_config(data, msg=f"{vlan.name}: Prepared config")

    def _ovs_extra_cfg_eq_val(self, ovs_extra, cmd_map, data):
        """Parse ovs extra of the format key=value

        Parse the ovs_extra fields where the configs are in key=value format
        Example: ovs-vsctl set Bridge $name <config>=<value>
                 ovs-vsctl set Interface $name <config>=<value>
        :param ovs_extra: given ovs extra as string
        :param cmd_map: A map of the available ovs_extra commands, actions
        :param data: The device data that will be modified after the parsing
        :raises ConfigurationError: Invalid ovs_extra format
        """
        index = 0
        for a, b in zip(ovs_extra, cmd_map['command']):
            if not re.match(b, a, re.IGNORECASE):
                return False
            index = index + 1
        for idx in range(index, len(ovs_extra)):
            value = None
            for cfg in cmd_map['action']:
                if re.match(cfg['config'], ovs_extra[idx], re.IGNORECASE):
                    value = None
                    if 'value' in cfg:
                        value = cfg['value']
                    elif 'value_pattern' in cfg:
                        m = re.search(cfg['value_pattern'], ovs_extra[idx])
                        if m:
                            value = _get_type_value(m.group(1))
                    if value is None:
                        msg = (
                            "ovs_extra: Invalid format detected. \n"
                            f"{' -- '.join(ovs_extra)}"
                        )
                        raise os_net_config.ConfigurationError(msg)
                    config = _add_sub_tree(data, cfg["sub_tree"])
                    if cfg["nm_config"]:
                        key = cfg["nm_config"]
                        config[key] = value
                    elif cfg["nm_config_regex"]:
                        m = re.search(cfg["nm_config_regex"], ovs_extra[idx])
                        if m:
                            key = m.group(1)
                            config[key] = value
                        else:
                            msg = (
                                "ovs_extra: Invalid format detected.\n"
                                f"{' -- '.join(ovs_extra)}"
                            )
                            raise os_net_config.ConfigurationError(msg)
                    else:
                        msg = 'NM config not found'
                        raise os_net_config.ConfigurationError(msg)
                    logger.info(
                        "%s=%s", "->".join(cfg["sub_tree"] + [(key)]), value
                    )

    def _ovs_extra_cfg_val(self, ovs_extra, cmd_map, data):
        """Parse ovs extra where key,value are seperated by spaces

        Parse ovs extra fields where key and value are seperated by spaces
        Example: ovs-vsctl br-set-external-id $name key [value]

        :param ovs_extra: given ovs extra as string
        :param cmd_map: A map of the available ovs_extra commands, actions
        :param data: The device data that will be modified after the parsing
        :raises ConfigurationError: Invalid ovs_extra format
        """
        index = 0
        for a, b in zip(ovs_extra, cmd_map['command']):
            if not re.match(b, a, re.IGNORECASE):
                return False
            index = index + 1
        if len(ovs_extra) > (index + 1):
            value = None
            for cfg in cmd_map['action']:
                if re.match(cfg['config'], ovs_extra[index], re.IGNORECASE):
                    value = None
                    if 'value' in cfg:
                        value = cfg['value']
                    elif 'value_pattern' in cfg:
                        m = re.search(cfg['value_pattern'],
                                      ovs_extra[index + 1])
                        if m:
                            value = _get_type_value(m.group(1))
                    if value is None:
                        msg = (
                            "ovs_extra: Invalid format detected.\n"
                            f"{' -- '.join(ovs_extra)}"
                        )
                        raise os_net_config.ConfigurationError(msg)
                    config = _add_sub_tree(data, cfg['sub_tree'])
                    if cfg["nm_config"]:
                        key = cfg["nm_config"]
                        config[key] = value
                    elif cfg['nm_config_regex']:
                        m = re.search(cfg['nm_config_regex'], ovs_extra[index])
                        if m:
                            key = m.group(1)
                            config[key] = value
                        else:
                            msg = (
                                "ovs_extra: Invalid format detected.\n"
                                f"{' -- '.join(ovs_extra)}"
                            )
                            raise os_net_config.ConfigurationError(msg)
                    else:
                        msg = 'NM config not found'
                        raise os_net_config.ConfigurationError(msg)
                    logger.info(
                        "%s=%s", "->".join(cfg["sub_tree"] + [key]), value
                    )

    def parse_ovs_extra_for_bond(self, ovs_extras, name, data):
        """Parse ovs extra for bonding options

        Parse ovs extra fields for the bonding options

        :param ovs_extras: given ovs extra as string
        :param name: Bond name
        :param data: The bond data that will be modified after the parsing
        """
        # Here the nm_config bond_mode matches the ovs_options
        # and not the Nmstate schema
        port_cfg = [
            {'config': r'^bond_mode=[\w+]',
             'sub_tree': [],
             'nm_config': 'bond_mode',
             'value_pattern': r'^bond_mode=(.+?)$'},
            {'config': r'^lacp=[\w+]',
             'sub_tree': [],
             'nm_config': 'lacp',
             'value_pattern': r'^lacp=(.+?)$'},
            {'config': r'^bond_updelay=[\w+]',
             'sub_tree': [],
             'nm_config': 'bond_updelay',
             'value_pattern': r'^bond_updelay=(.+?)$'},
            {'config': r'^other_config:[\w+]',
             'sub_tree': [],
             'nm_config': None,
             'nm_config_regex': r'^(.+?)=.*$',
             'value_pattern': r'^other_config:.*=(.+?)$'}]

        # ovs-vsctl set Port $name <config>=<value>
        cfg_eq_val_pair = [{'command': ['set', 'port',
                                        '({name}|%s)' % name],
                            'action': port_cfg}]

        for ovs_extra in ovs_extras:
            logger.debug("%s: Parse - %s", name, ovs_extra)
            ovs_extra_cmd = ovs_extra.split(' ')
            for cmd_map in cfg_eq_val_pair:
                self._ovs_extra_cfg_eq_val(ovs_extra_cmd, cmd_map, data)

    def parse_ovs_extra(self, ovs_extras, name, data):
        """Parse ovs extra for bridges, ports

        :param ovs_extras: given ovs extra as string
        :param name: bridge/port name
        :param data: The OVS Interface or Bridge data that will
            be modified after the parsing
        """

        bridge_cfg = [{'config': r'^fail_mode=[\w+]',
                       'sub_tree': [OVSBridge.CONFIG_SUBTREE,
                                    OVSBridge.OPTIONS_SUBTREE],
                       'nm_config': OVSBridge.Options.FAIL_MODE,
                       'value_pattern': r'^fail_mode=(.+?)$'},
                      {'config': r'^mcast_snooping_enable=[\w+]',
                       'sub_tree': [OVSBridge.CONFIG_SUBTREE,
                                    OVSBridge.OPTIONS_SUBTREE],
                       'nm_config': OVSBridge.Options.MCAST_SNOOPING_ENABLED,
                       'value_pattern': r'^mcast_snooping_enable=(.+?)$'},
                      {'config': r'^rstp_enable=[\w+]',
                       'sub_tree': [OVSBridge.CONFIG_SUBTREE,
                                    OVSBridge.OPTIONS_SUBTREE],
                       'nm_config': OVSBridge.Options.RSTP,
                       'value_pattern': r'^rstp_enable=(.+?)$'},
                      {'config': r'^stp_enable=[\w+]',
                       'sub_tree': [OVSBridge.CONFIG_SUBTREE,
                                    OVSBridge.OPTIONS_SUBTREE],
                       'nm_config': OVSBridge.Options.STP,
                       'value_pattern': r'^stp_enable=(.+?)$'},
                      {'config': r'^other_config:[\w+]',
                       'sub_tree': [OvsDB.KEY, OvsDB.OTHER_CONFIG],
                       'nm_config': None,
                       'nm_config_regex': r'^other_config:(.+?)=',
                       'value_pattern': r'^other_config:.*=(.+?)$'},
                      {'config': r'^other-config:[\w+]',
                       'sub_tree': [OvsDB.KEY, OvsDB.OTHER_CONFIG],
                       'nm_config': None,
                       'nm_config_regex': r'^other-config:(.+?)=',
                       'value_pattern': r'^other-config:.*=(.+?)$'}]

        iface_cfg = [{'config': r'^other_config:[\w+]',
                      'sub_tree': [OvsDB.KEY, OvsDB.OTHER_CONFIG],
                      'nm_config': None,
                      'nm_config_regex': r'^other_config:(.+?)=',
                      'value_pattern': r'^other_config:.*=(.+?)$'},
                     {'config': r'^other-config:[\w+]',
                      'sub_tree': [OvsDB.KEY, OvsDB.OTHER_CONFIG],
                      'nm_config': None,
                      'nm_config_regex': r'^other-config:(.+?)=',
                      'value_pattern': r'^other-config:.*=(.+?)$'},
                     {'config': r'^options:n_rxq_desc=[\w+]',
                      'sub_tree': [OVSInterface.DPDK_CONFIG_SUBTREE],
                      'nm_config': OVSInterface.Dpdk.N_RXQ_DESC,
                      'value_pattern': r'^options:n_rxq_desc=(.+?)$'},
                     {'config': r'^options:n_txq_desc=[\w+]',
                      'sub_tree': [OVSInterface.DPDK_CONFIG_SUBTREE],
                      'nm_config': OVSInterface.Dpdk.N_TXQ_DESC,
                      'value_pattern': r'^options:n_txq_desc=(.+?)$'}]

        external_id_cfg = [{'sub_tree': [OvsDB.KEY, OvsDB.EXTERNAL_IDS],
                            'config': r'.*',
                            'nm_config': None,
                            'nm_config_regex': r'^(.+?)$',
                            'value_pattern': r'^(.+?)$'}]
        cfg_eq_val_pair = [{'command': ['set', 'bridge', '({name}|%s)' % name],
                            'action': bridge_cfg},
                           {'command': ['set', 'interface',
                                        '({name}|%s)' % name],
                            'action': iface_cfg}]

        cfg_val_pair = [{'command': ['br-set-external-id',
                                     '({name}|%s)' % name],
                         'action': external_id_cfg}]
        # ovs-vsctl set Bridge $name <config>=<value>
        # ovs-vsctl set Interface $name <config>=<value>
        # ovs-vsctl br-set-external-id $name key [value]
        for ovs_extra in ovs_extras:
            logger.info("%s: Parse - %s", name, ovs_extra)
            ovs_extra_cmd = ovs_extra.split(' ')
            for cmd_map in cfg_eq_val_pair:
                self._ovs_extra_cfg_eq_val(ovs_extra_cmd, cmd_map, data)
            for cmd_map in cfg_val_pair:
                self._ovs_extra_cfg_val(ovs_extra_cmd, cmd_map, data)

    def parse_ovs_extra_for_ports(self, ovs_extras, bridge_name, data):
        """Parse ovs extra for VLAN

        :param ovs_extras: given ovs extra as string
        :param bridge_name: bridge name
        :param data: The interface data that will be modified after
            the parsing
        """
        port_vlan_cfg = [{'config': r'^tag=[\w+]',
                          'sub_tree': [OVSBridge.Port.VLAN_SUBTREE],
                          'nm_config': OVSBridge.Port.Vlan.TAG,
                          'value_pattern': r'^tag=(.+?)$'},
                         {'config': r'^tag=[\w+]',
                          'sub_tree': [OVSBridge.Port.VLAN_SUBTREE],
                          'nm_config': OVSBridge.Port.Vlan.MODE,
                          'value': 'access'}]
        cfg_eq_val_pair = [{'command': ['set', 'port',
                                        '({name}|%s)' % bridge_name],
                            'action': port_vlan_cfg}]
        for ovs_extra in ovs_extras:
            logger.info("%s: Parse - %s", bridge_name, ovs_extra)
            ovs_extra_cmd = ovs_extra.split(' ')
            for cmd_map in cfg_eq_val_pair:
                self._ovs_extra_cfg_eq_val(ovs_extra_cmd, cmd_map, data)

    def add_bridge(self, bridge, dpdk=False):
        """Add an OvsBridge object to the net config object.

        :param bridge: The OvsBridge object to add.
        :raises ConfigurationError: Invalid member types
        """

        # Create the internal ovs interface. Some of the settings of the
        # bridge like MTU, ip address are to be applied on this interface
        if self.migration_enabled:
            self._clean_iface(bridge.name, OVSBridge.TYPE)

        ovs_port_name = bridge.name
        if bridge.primary_interface_name:
            mac = self.interface_mac(bridge.primary_interface_name)
        else:
            mac = None

        ovs_interface_port = objects.OvsInterface(
            ovs_port_name, use_dhcp=bridge.use_dhcp,
            use_dhcpv6=bridge.use_dhcpv6,
            addresses=bridge.addresses, routes=bridge.routes,
            rules=bridge.rules, mtu=bridge.mtu, primary=False,
            nic_mapping=None, persist_mapping=None,
            defroute=bridge.defroute, dhclient_args=bridge.dhclient_args,
            dns_servers=bridge.dns_servers,
            nm_controlled=None, onboot=bridge.onboot,
            domain=bridge.domain, hwaddr=mac)
        self.add_ovs_interface(ovs_interface_port)

        ovs_int_port = {'name': ovs_interface_port.name}
        if bridge.ovs_extra:
            self.parse_ovs_extra_for_ports(bridge.ovs_extra,
                                           bridge.name, ovs_int_port)

        logger.info("%s: adding bridge", bridge.name)

        # Clear the settings from the bridge, since these will be applied
        # on the interface
        if bridge.routes:
            bridge.routes.clear()
        bridge.defroute = False
        if bridge.dns_servers:
            bridge.dns_servers.clear()
        if bridge.domain:
            bridge.domain.clear()
        if bridge.mtu:
            bridge.mtu = None
        data = self._add_common(bridge)

        data[Interface.TYPE] = OVSBridge.TYPE
        # address bits can't be on the ovs-bridge
        del data[Interface.IPV4]
        del data[Interface.IPV6]
        ovs_bridge_options = {OVSBridge.Options.FAIL_MODE:
                              objects.DEFAULT_OVS_BRIDGE_FAIL_MODE,
                              OVSBridge.Options.MCAST_SNOOPING_ENABLED: False,
                              OVSBridge.Options.RSTP: False,
                              OVSBridge.Options.STP: False}

        if bridge.name in self.bridge_data:
            data[OVSBridge.CONFIG_SUBTREE] = self.bridge_data[
                bridge.name][OVSBridge.CONFIG_SUBTREE]
            data[OVSBridge.CONFIG_SUBTREE
                 ][OVSBridge.OPTIONS_SUBTREE] = ovs_bridge_options
        else:
            data[OVSBridge.CONFIG_SUBTREE] = {
                OVSBridge.OPTIONS_SUBTREE: ovs_bridge_options,
                OVSBridge.PORT_SUBTREE: [],
            }
        data[OvsDB.KEY] = {OvsDB.EXTERNAL_IDS: {},
                           OvsDB.OTHER_CONFIG: {}}
        bridge.ovs_extra.append("set bridge %s other-config:mac-table-size=%d"
                                % (bridge.name, common.MAC_TABLE_SIZE))
        if bridge.primary_interface_name:
            mac = self.interface_mac(bridge.primary_interface_name)
            bridge.ovs_extra.append("set bridge %s other_config:hwaddr=%s" %
                                    (bridge.name, mac))
        self.parse_ovs_extra(bridge.ovs_extra, bridge.name, data)

        if dpdk:
            ovs_bridge_options[OVSBridge.Options.DATAPATH] = 'netdev'
        if bridge.members:
            members = []
            ovs_bond = False
            ovs_port = False
            for member in bridge.members:
                if (isinstance(member, objects.OvsBond) or
                        isinstance(member, objects.OvsDpdkBond)):
                    bond_options = {}
                    self.parse_ovs_extra_for_bond(
                        member.ovs_extra, member.name, bond_options)
                    logger.debug(
                        "%s: Bond options from ovs_extra\n%s",
                        member.name,
                        bond_options,
                    )
                    if ovs_port:
                        msg = (
                            f"{bridge.name}: Ovs Bond and ovs port can't"
                            "be members to the same ovs bridge"
                        )
                        raise os_net_config.ConfigurationError(msg)
                    if member.primary_interface_name:
                        add_bond_setting = "other_config:bond-primary="\
                                           f"{member.primary_interface_name}"
                        if member.ovs_options:
                            member.ovs_options = member.ovs_options + " " +\
                                add_bond_setting
                        else:
                            member.ovs_options = add_bond_setting

                    logger.debug(
                        "%s: Bond options from ovs_options:\n%s",
                        member.name,
                        member.ovs_options,
                    )
                    bond_options |= parse_bonding_options(member.ovs_options)
                    logger.info(
                        "%s: Aggregated bond options - %s",
                        member.name,
                        bond_options,
                    )
                    bond_data = set_ovs_bonding_options(bond_options)
                    bond_port = [{
                        OVSBridge.Port.LINK_AGGREGATION_SUBTREE: bond_data,
                        OVSBridge.Port.NAME: member.name},
                        ovs_int_port]
                    data[OVSBridge.CONFIG_SUBTREE
                         ][OVSBridge.PORT_SUBTREE] = bond_port

                    ovs_bond = True
                    if member.members:
                        members = [m.name for m in member.members]
                elif ovs_bond:
                    msg = (
                        f"{bridge.name}: ovs bond and ovs port can't be"
                        "members to the ovs bridge"
                    )
                    raise os_net_config.ConfigurationError(msg)
                else:
                    ovs_port = True
                    members.append(member.name)
            if members:
                bps = self.get_ovs_ports(members)
            else:
                msg = f"{bridge.name}: no member added to ovs bridge"
                raise os_net_config.ConfigurationError(msg)

            self.member_names[bridge.name] = members

            if ovs_port:
                # Add the internal ovs interface
                bps.append(ovs_int_port)
                data[OVSBridge.CONFIG_SUBTREE][
                    OVSBridge.PORT_SUBTREE].extend(bps)
                bps_names = [port.get("name", "") for port in bps]
                logger.debug(
                    "%s: adding ovs ports - %s",
                    bridge.name,
                    " ".join(bps_names),
                )
            elif ovs_bond:
                bond_data[OVSBridge.Port.LinkAggregation.PORT_SUBTREE] = bps
                bps_names = [port.get("name", "") for port in bps]
                logger.debug(
                    "%s: adding ovs ports - %s",
                    bridge.members[0].name,
                    " ".join(bps_names),
                )

        self.bridge_data[bridge.name] = data
        self.__dump_config(data, msg=f"{bridge.name}: Prepared config")

    def add_ovs_user_bridge(self, bridge):
        """Add an OvsUserBridge object to the net config object.

        :param bridge: The OvsUserBridge object to add.
        """
        logger.info("%s: adding ovs user bridge", bridge.name)
        self.add_bridge(bridge, dpdk=True)

    def attach_patch_port_with_bridge(self, patch_port):
        """Add a patch port to bridge from patch port settings in json.

        :param patch_port: The patch_port object to add.
        """
        patch_br_data = self.bridge_data.get(patch_port.bridge_name, {})
        if OVSBridge.CONFIG_SUBTREE not in patch_br_data:
            patch_br_data[OVSBridge.CONFIG_SUBTREE] = {
                OVSBridge.OPTIONS_SUBTREE: {},
                OVSBridge.PORT_SUBTREE: [],
            }
        config = patch_br_data[OVSBridge.CONFIG_SUBTREE]
        if OVSBridge.PORT_SUBTREE not in config:
            config[OVSBridge.PORT_SUBTREE] = []
        port = config[OVSBridge.PORT_SUBTREE]
        patch_port_config = {OVSBridge.Port.NAME: patch_port.name}
        if patch_port_config not in port:
            port.append(patch_port_config)

        self.bridge_data[patch_port.bridge_name] = patch_br_data
        self.__dump_config(
            patch_br_data, msg=f"{patch_port.bridge_name}: Prepared config"
        )
        return

    def add_ovs_patch_port(self, ovs_patch_port):
        """Add a OvsPatchPort object to the net config object.

        :param ovs_patch_port: The OvsPatchPort object to add.
        """
        if self.migration_enabled:
            self._clean_iface(ovs_patch_port.name, OVSInterface.TYPE)

        logger.info("%s: adding ovs patch port", ovs_patch_port.name)
        data = self._add_common(ovs_patch_port)
        data[Interface.TYPE] = OVSInterface.TYPE
        data[Interface.STATE] = InterfaceState.UP
        data[OVSInterface.PATCH_CONFIG_SUBTREE] = \
            {OVSInterface.Patch.PEER: ovs_patch_port.peer}
        self.interface_data[ovs_patch_port.name] = data

        self.attach_patch_port_with_bridge(ovs_patch_port)
        self.__dump_config(data, msg=f"{ovs_patch_port.name}: Prepared config")

    def add_ovs_interface(self, ovs_interface):
        """Add a OvsInterface object to the net config object.

        :param ovs_interface: The OvsInterface object to add.
        """
        if self.migration_enabled:
            self._clean_iface(ovs_interface.name, OVSInterface.TYPE)

        logger.info("%s: adding ovs interface", ovs_interface.name)
        data = self._add_common(ovs_interface)
        data[Interface.TYPE] = OVSInterface.TYPE
        data[Interface.STATE] = InterfaceState.UP

        if ovs_interface.hwaddr:
            data[Interface.MAC] = ovs_interface.hwaddr
        self.interface_data[ovs_interface.name + '-if'] = data
        self.__dump_config(data, msg=f"{ovs_interface.name}: Prepared config")

    def add_ovs_dpdk_port(self, ovs_dpdk_port):
        """Add a OvsDpdkPort object to the net config object.

        :param ovs_dpdk_port: The OvsDpdkPort object to add.
        """
        if self.migration_enabled:
            self._clean_iface(ovs_dpdk_port.name, OVSInterface.TYPE)

        logger.info("%s: adding ovs dpdk port", ovs_dpdk_port.name)

        # DPDK Port will have only one member of type Interface, validation
        # checks are added at the object creation stage.
        ifname = ovs_dpdk_port.members[0].name

        data = self._add_common(ovs_dpdk_port)
        data[Interface.TYPE] = OVSInterface.TYPE
        data[Interface.STATE] = InterfaceState.UP

        if isinstance(ovs_dpdk_port.members[0], objects.SriovVF):
            # in case of VFs the DPDK driver will be bound using
            # dispatcher script
            pci_address = ovs_dpdk_port.members[0].pci_address
            utils.update_dpdk_map(ifname,
                                  ovs_dpdk_port.driver)
            # In NIC partitioning scenario with dpdk ports, the VF
            # configuration is skipped since add_sriov_vf() will not be
            # called for dpdk ports. Adding the VF config here.
            self.__add_sriov_vf_config(ovs_dpdk_port.members[0])
        else:
            # Bind the DPDK driver for interface objects
            utils.bind_dpdk_interfaces(ifname, ovs_dpdk_port.driver,
                                       self.noop)
            pci_address = utils.get_dpdk_devargs(ifname,
                                                 noop=self.noop)

        data[OVSInterface.DPDK_CONFIG_SUBTREE
             ] = {OVSInterface.Dpdk.DEVARGS: pci_address}
        if ovs_dpdk_port.rx_queue:
            data[OVSInterface.DPDK_CONFIG_SUBTREE
                 ][OVSInterface.Dpdk.RX_QUEUE] = ovs_dpdk_port.rx_queue
        if ovs_dpdk_port.rx_queue_size:
            data[OVSInterface.DPDK_CONFIG_SUBTREE
                 ][OVSInterface.Dpdk.N_RXQ_DESC] = ovs_dpdk_port.rx_queue_size
        if ovs_dpdk_port.tx_queue_size:
            data[OVSInterface.DPDK_CONFIG_SUBTREE
                 ][OVSInterface.Dpdk.N_TXQ_DESC] = ovs_dpdk_port.tx_queue_size
        data[OvsDB.KEY] = {OvsDB.EXTERNAL_IDS: {},
                           OvsDB.OTHER_CONFIG: {}}
        if ovs_dpdk_port.ovs_extra:
            logger.info(
                "%s: Parse - %s", ovs_dpdk_port.name, ovs_dpdk_port.ovs_extra
            )
            self.parse_ovs_extra(ovs_dpdk_port.ovs_extra,
                                 ovs_dpdk_port.name, data)
        self.interface_data[ovs_dpdk_port.name] = data
        self.__dump_config(data, msg=f"{ovs_dpdk_port.name}: Prepared config")

    def add_linux_bridge(self, bridge):
        """Add a LinuxBridge object to the net config object.

        :param bridge: The LinuxBridge object to add.
        """
        if self.migration_enabled:
            self._clean_iface(bridge.name, InterfaceType.LINUX_BRIDGE)

        logger.info("%s: adding linux bridge", bridge.name)
        data = self._add_common(bridge)
        self.linuxbridge_data[bridge.name] = data
        self.__dump_config(data, msg=f"{bridge.name}: Prepared config")

    def add_bond(self, bond):
        """Add an OvsBond object to the net config object.

        :param bond: The OvsBond object to add.
        """
        # The ovs bond is already added in add_bridge()
        logger.info("%s: adding bond", bond.name)
        return

    def add_ovs_dpdk_bond(self, bond):
        """Add an OvsDpdkBond object to the net config object.

        :param bond: The OvsBond object to add.
        """
        logger.info("%s: adding ovs_dpdk_bond", bond.name)
        for member in bond.members:
            if bond.mtu:
                member.mtu = bond.mtu
            if bond.rx_queue:
                member.rx_queue = bond.rx_queue
            if bond.rx_queue_size:
                member.rx_queue_size = bond.rx_queue_size
            if bond.tx_queue_size:
                member.tx_queue_size = bond.tx_queue_size
            if bond.ovs_extra:
                member.ovs_extra = bond.ovs_extra
            self.add_ovs_dpdk_port(member)
        return

    def add_linux_bond(self, bond):
        """Add a LinuxBond object to the net config object.

        :param bond: The LinuxBond object to add.
        """
        if self.migration_enabled:
            self._clean_iface(bond.name, InterfaceType.BOND)

        logger.info("%s: adding linux bond", bond.name)
        data = self._add_common(bond)

        data[Interface.TYPE] = InterfaceType.BOND
        data[Interface.STATE] = InterfaceState.UP

        bond_options = {}
        if bond.bonding_options:
            bond_options = parse_bonding_options(bond.bonding_options)

        bond_data = set_linux_bonding_options(
            bond_options, primary_iface=bond.primary_interface_name)
        if bond_data:
            data[Bond.CONFIG_SUBTREE] = bond_data

        if bond.members:
            members = [member.name for member in bond.members]
            self.member_names[bond.name] = members
            data[Bond.CONFIG_SUBTREE][Bond.PORT] = members

        self.linuxbond_data[bond.name] = data
        self.__dump_config(data, msg=f"{bond.name}: Prepared config")

    def add_sriov_pf(self, sriov_pf):
        """Add a SriovPF object to the net config object

        :param sriov_pf: The SriovPF object to add
        :raises ConfigurationError: Unsupported link mode or mismatch in SR-IOV
            capability
        """
        if self.migration_enabled:
            self._clean_iface(sriov_pf.name, InterfaceType.ETHERNET)

        logger.info("%s: adding sriov pf", sriov_pf.name)
        if sriov_pf.vdpa or sriov_pf.link_mode == 'switchdev':
            msg = (
                f"{sriov_pf.name}: switchdev/vDPA is not supported "
                "by nmstate provider yet."
            )
            raise os_net_config.ConfigurationError(msg)
        if common.is_pf_attached_to_guest(sriov_pf.name):
            logger.info(
                "%s: Attached to guest, skip configuring", sriov_pf.name
            )
            return

        data = self._add_common(sriov_pf)
        data[Interface.TYPE] = InterfaceType.ETHERNET
        data[Ethernet.CONFIG_SUBTREE] = {}

        # Validate the maximum VFs allowed by hardware against
        # the desired numvfs
        max_vfs = utils.get_totalvfs(sriov_pf.name)
        if max_vfs <= 0:
            msg = (f'{sriov_pf.name}: SR-IOV is not supported.'
                   'Check BIOS settings')
            raise os_net_config.ConfigurationError(msg)
        elif max_vfs >= sriov_pf.numvfs:
            data[Ethernet.CONFIG_SUBTREE][Ethernet.SRIOV_SUBTREE] = {
                Ethernet.SRIOV.TOTAL_VFS: sriov_pf.numvfs,
                Ethernet.SRIOV.DRIVERS_AUTOPROBE: sriov_pf.drivers_autoprobe,
            }
        else:
            msg = (
                f"{sriov_pf.name}: maximum numvfs supported "
                f"({max_vfs}) is lesser than user requested "
                f"numvfs ({sriov_pf.numvfs})"
            )
            raise os_net_config.ConfigurationError(msg)

        if sriov_pf.promisc:
            data[Interface.ACCEPT_ALL_MAC_ADDRESSES] = True

        if sriov_pf.link_mode == 'legacy':
            data[Ethtool.CONFIG_SUBTREE] = {}
            data[Ethtool.CONFIG_SUBTREE][Ethtool.Feature.CONFIG_SUBTREE] = {
                'hw-tc-offload': False}

        if sriov_pf.ethtool_opts:
            self.add_ethtool_config(sriov_pf.name, data,
                                    sriov_pf.ethtool_opts)

        self.sriov_vf_data[sriov_pf.name] = [None] * sriov_pf.numvfs
        self.sriov_pf_data[sriov_pf.name] = data
        self.vf_drv_override[sriov_pf.name] = {}
        self.need_pf_config = True
        self.__dump_config(data, msg=f"{sriov_pf.name}: Prepared config")

    def __add_sriov_vf_config(self, sriov_vf):
        # sriov_vf_data is a list of vf configuration data of size numvfs.
        # The vfid is used as index.
        if sriov_vf.device not in self.sriov_vf_data:
            msg = f"{sriov_vf.device}: PF is not configured yet"
            raise os_net_config.ConfigurationError(msg)

        vf_config = self.get_vf_config(sriov_vf)
        logger.debug(
            "%s-%d: vf config %s", sriov_vf.device, sriov_vf.vfid, vf_config
        )

        self.sriov_vf_data[sriov_vf.device][sriov_vf.vfid] = vf_config
        self.need_vf_config = True

    def add_sriov_vf(self, sriov_vf):
        """Add a SriovVF object to the net config object

        :param sriov_vf: The SriovVF object to add
        :raises ConfigurationError: Indicates that VF config is performed
            without configuring the PF.
        """
        if self.migration_enabled:
            self._clean_iface(sriov_vf.name, InterfaceType.ETHERNET)

        logger.info("%s-%d: adding vf", sriov_vf.device, sriov_vf.vfid)
        data = self._add_common(sriov_vf)
        data[Interface.TYPE] = InterfaceType.ETHERNET
        data[Ethernet.CONFIG_SUBTREE] = {}
        if sriov_vf.promisc:
            data[Interface.ACCEPT_ALL_MAC_ADDRESSES] = True
        self.interface_data[sriov_vf.name] = data

        if sriov_vf.ethtool_opts:
            self.add_ethtool_config(sriov_vf.name, data,
                                    sriov_vf.ethtool_opts)
        self.__add_sriov_vf_config(sriov_vf)
        self.__dump_config(
            data, msg=(f"{sriov_vf.device}-{sriov_vf.vfid}: Prepared config")
        )

    def add_ib_interface(self, ib_interface):
        """Add an InfiniBand interface object to the net config object.

        :param ib_interface: The InfiniBand interface object to add.
        """
        if self.migration_enabled:
            self._clean_iface(ib_interface.name, InterfaceType.INFINIBAND)

        logger.info("%s: adding ib_interface", ib_interface.name)
        data = self._add_common(ib_interface)
        data[Interface.TYPE] = InterfaceType.INFINIBAND
        if ib_interface.ethtool_opts:
            self.add_ethtool_config(ib_interface.name, data,
                                    ib_interface.ethtool_opts)
        # Default mode is set to 'datagram' since 'connected' is not
        # supported in some devices
        config = {}
        config[InfiniBand.MODE] = InfiniBand.Mode.DATAGRAM
        data[InfiniBand.CONFIG_SUBTREE] = config
        self.interface_data[ib_interface.name] = data
        self.__dump_config(data, msg=f"{ib_interface.name}: Prepared config")

    def add_ib_child_interface(self, ib_child_interface):
        """Add an InfiniBand child interface object to the net config object.

        :param ib_child_interface: The InfiniBand child
         interface object to add.
        """
        if self.migration_enabled:
            self._clean_iface(ib_child_interface.name,
                              InterfaceType.INFINIBAND)

        logger.info("%s: adding ib_child_interface", ib_child_interface.name)
        data = self._add_common(ib_child_interface)
        data[Interface.TYPE] = InterfaceType.INFINIBAND
        config = {}
        config[InfiniBand.PKEY] = ib_child_interface.pkey_id
        config[InfiniBand.BASE_IFACE] = ib_child_interface.parent
        # Default mode is set to 'datagram' since 'connected' is not
        # supported in some devices
        config[InfiniBand.MODE] = InfiniBand.Mode.DATAGRAM
        data[InfiniBand.CONFIG_SUBTREE] = config
        self.interface_data[ib_child_interface.name] = data
        self.__dump_config(
            data, msg=f"{ib_child_interface.name}: Prepared config"
        )

    def apply(self, cleanup=False, activate=True, config_rules_dns=True):
        """Apply the network configuration.

        :param cleanup: A boolean which indicates whether any undefined
            (existing but not present in the object model) interface
            should be disabled and deleted.
        :param activate: A boolean which indicates if the config should
            be activated by stopping/starting interfaces
            NOTE: if cleanup is specified we will deactivate interfaces even
            if activate is false
        :param config_rules_dns: A boolean that indicates if the rules should
            be applied. This makes sure that the rules are configured only if
            config_rules_dns is set to True.
        :raises ConfigurationError: Failed to apply the generated templates.
        :returns: a dict of the format: filename/data which contains info
            for each file that was changed (or would be changed if in --noop
            mode).
        Note the noop mode is set via the constructor noop boolean
        """
        logger.info('applying network configs....')

        add_routes = []
        del_routes = []

        all_iface_names = []

        updated_interfaces = {}
        updated_pfs = []

        if self.need_pf_config:
            pf_devs = self.apply_pf_config(activate)
            updated_pfs.extend(pf_devs)

        if self.need_vf_config:
            pf_devs = self.apply_vf_config(activate)
            updated_pfs.extend(pf_devs)

        apply_data = {}
        for pf_name in self.sriov_pf_data.keys():
            add_route, del_route = self.generate_routes(pf_name)
            add_routes.extend(add_route)
            del_routes.extend(del_route)

        for interface_name, iface_data in self.interface_data.items():
            all_iface_names.append(interface_name)
            iface_state = self.iface_state(interface_name)
            self.remove_empty_dispatch_scripts(iface_state, iface_data)
            if not is_dict_subset(iface_state, iface_data):
                updated_interfaces[interface_name] = iface_data
            else:
                logger.info("%s : no change required", interface_name)
            add_route, del_route = self.generate_routes(interface_name)
            add_routes.extend(add_route)
            del_routes.extend(del_route)

        for bridge_name, bridge_data in self.bridge_data.items():
            all_iface_names.append(bridge_name)
            bridge_state = self.iface_state(bridge_name)
            self.remove_empty_dispatch_scripts(bridge_state, bridge_data)
            if not is_dict_subset(bridge_state, bridge_data):
                updated_interfaces[bridge_name] = bridge_data
            else:
                logger.info("%s: no change required", bridge_name)

            add_route, del_route = self.generate_routes(bridge_name)
            add_routes.extend(add_route)
            del_routes.extend(del_route)

        for bond_name, bond_data in self.linuxbond_data.items():
            all_iface_names.append(bond_name)
            bond_state = self.iface_state(bond_name)
            self.remove_empty_dispatch_scripts(bond_state, bond_data)
            if not is_dict_subset(bond_state, bond_data):
                updated_interfaces[bond_name] = bond_data
            else:
                logger.info("%s: no change required", bond_name)
            add_route, del_route = self.generate_routes(bond_name)
            add_routes.extend(add_route)
            del_routes.extend(del_route)

        for vlan_name, vlan_data in self.vlan_data.items():
            all_iface_names.append(vlan_name)
            vlan_state = self.iface_state(vlan_name)
            self.remove_empty_dispatch_scripts(vlan_state, vlan_data)
            if not is_dict_subset(vlan_state, vlan_data):
                updated_interfaces[vlan_name] = vlan_data
            else:
                logger.info("%s: no change required", vlan_name)
            add_route, del_route = self.generate_routes(vlan_name)
            add_routes.extend(add_route)
            del_routes.extend(del_route)

        if cleanup:
            self.cleanup_all_ifaces(exclude_nics=all_iface_names)

        if updated_interfaces:
            apply_data = self.set_ifaces(list(updated_interfaces.values()))
            if activate:
                self.nmstate_apply(apply_data, verify=True)
        if del_routes:
            apply_data = self.set_routes(del_routes)
            if activate:
                self.nmstate_apply(apply_data, verify=True)
        if add_routes:
            apply_data = self.set_routes(add_routes)
            if activate:
                self.nmstate_apply(apply_data, verify=True)

        if config_rules_dns:
            add_rules, del_rules = self.generate_rules()

            if del_rules:
                apply_data = self.set_rules(del_rules)
                if activate:
                    self.nmstate_apply(apply_data, verify=True)

            if add_rules:
                rules_applied = self.set_rules(add_rules)
                if activate:
                    self.nmstate_apply(rules_applied, verify=True)

            apply_data = self.set_dns()
            if activate:
                self.nmstate_apply(apply_data, verify=True)

        if activate:
            if self.errors:
                message = 'Failure(s) occurred when applying configuration'
                logger.error(message)
                for e in self.errors:
                    logger.error(str(e))
                self.rollback_to_initial_settings()
                raise os_net_config.ConfigurationError(message)

            try:
                if rules_applied:
                    common.write_yaml_config(CONFIG_RULES_FILE, rules_applied)
            except NameError:
                no_rules = self.set_rules(rule_data=[])
                common.write_yaml_config(CONFIG_RULES_FILE, no_rules)

        self.interface_data = {}
        self.bridge_data = {}
        self.linuxbond_data = {}
        self.vlan_data = {}

        # the PF config and VF config are applied separately above
        for pf in updated_pfs:
            updated_interfaces[pf] = self.sriov_pf_data[pf]

        logger.debug(
            "Updated the interfaces: %s", " ".join(updated_interfaces.keys())
        )

        logger.info(
            "Succesfully applied the network config with nmstate provider"
        )
        return updated_interfaces
