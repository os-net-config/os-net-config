# -*- coding: utf-8 -*-

# Copyright 2024 Red Hat, Inc.
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

import argparse
import logging
import os
import re
import sys
import yaml

from collections import defaultdict
from os_net_config import common
from os_net_config import dcb_netlink
from os_net_config import objects
from os_net_config import utils
from os_net_config import validator
from oslo_concurrency import processutils
from pyroute2 import netlink
from pyroute2.netlink.nlsocket import NetlinkSocket
from pyroute2.netlink.rtnl import RTM_GETDCB
from pyroute2.netlink.rtnl import RTM_SETDCB

# Maximum retries for getting the reply for
# netlink msg with correct sequence number
DCB_MAX_RETRIES = 3

# Bitmask indicating the mode - OS Controlled vs FW Controlled
DCB_CAP_DCBX_HOST = 0x1

IEEE_8021QAZ_TSA_STRICT = 0
IEEE_8021QAZ_TSA_ETS = 2
IEEE_8021QAZ_TSA_VENDOR = 255

logger = logging.getLogger(__name__)


class DCBErrorException(ValueError):
    pass


class DcbApp:
    def __init__(self, selector, priority, protocol):
        self.selector = selector
        self.priority = priority
        self.protocol = protocol

    def is_equal(self, dcbapp2):
        if (self.selector == dcbapp2.selector and
                self.priority == dcbapp2.priority and
                self.protocol == dcbapp2.protocol):
            return True
        return False

    def dump(self):
        log = (f'DcbApp {{Priority: {self.priority} '
               f'Protocol: {self.protocol} Selector: {self.selector}}}')
        return log


class DcbAppTable:
    def __init__(self):
        self.apps = {}

    def dump(self, selector):
        s = ["", "", "", "", "", "", "", ""]

        for i in self.apps.keys():
            if self.apps[i].selector == selector:
                s[self.apps[i].priority] += '%02d ' % self.apps[i].protocol

        msg = ""
        for i in range(8):
            pad = "\tprio:%d dscp:" % i
            while (len(s[i]) > 24):
                msg += pad + s[i][:24] + "\n"
                s[i] = s[i][24:]
            if s[i] != "":
                msg += pad + s[i]

        return msg

    def set_values(self, dcb_cfg):
        for i in self.apps.keys():
            dcb_cfg.set_ieee_app(self.apps[i].selector,
                                 self.apps[i].priority,
                                 self.apps[i].protocol)

    def count_app_selector(self, selector):
        count = 0
        for i in self.apps.keys():
            if self.apps[i].selector == selector:
                count = count + 1
        return count

    def del_app_entry(self, dcb_cfg,
                      selector=dcb_netlink.IEEE_8021QAZ_APP_SEL_DSCP):
        for i in self.apps.keys():
            if self.apps[i].selector == selector:
                dcb_cfg.del_ieee_app(self.apps[i].selector,
                                     self.apps[i].priority,
                                     self.apps[i].protocol)

    def set_default_dscp(self, dcb_cfg, selector, max_protocol):
        for i in range(max_protocol):
            dcb_cfg.set_ieee_app(selector, i >> 3, i)  # firmware default
        return


class DcbMessage(dcb_netlink.dcbmsg):
    def __init__(self, nlmsg=None):
        super(dcb_netlink.dcbmsg, self).__init__(nlmsg)
        self['family'] = 0

    def set_header(self, cmd, msg_type, seq):
        self['cmd'] = cmd
        self['header']['sequence_number'] = seq
        self['header']['pid'] = os.getpid()
        self['header']['type'] = msg_type
        self['header']['flags'] = netlink.NLM_F_REQUEST

    def set_attr(self, attr):
        self['attrs'] = attr


class DcbConfig():
    def __init__(self, device):
        self.device = device
        self._seq = 0
        self.nlsock = NetlinkSocket(family=netlink.NETLINK_ROUTE)
        self.nlsock.bind()

    def seq(self):
        self._seq += 1
        return self._seq

    def check_error(self, msg, seq):
        if msg['header']['sequence_number'] == seq:
            if msg['header']['type'] == netlink.NLMSG_ERROR:
                return netlink.NLMSG_ERROR
            return msg['header']['type']
        else:
            return -1

    def send_and_receive(self, cmd, msg_type, attr):
        msg = DcbMessage()
        seq = self.seq()
        msg.set_header(cmd=cmd, msg_type=msg_type,
                       seq=seq)
        iface_attr = ['DCB_ATTR_IFNAME', self.device]
        msg.set_attr(attr=[iface_attr] + attr)
        msg.encode()
        try:
            logger.debug(
                "%s: Sending message %s cmd %s attr %s",
                self.device,
                msg_type_to_name(msg_type),
                cmd_to_name(cmd),
                attr,
            )
            self.nlsock.sendto(msg.data, (0, 0))
        except Exception:
            e_msg = (f'{self.device}: Failed to send '
                     f'{msg_type_to_name(msg_type)}')
            raise DCBErrorException(e_msg)

        try:
            retry = 0
            while retry < DCB_MAX_RETRIES:
                rd_data = self.nlsock.recv(netlink.NLMSG_MAX_LEN)
                r_msg = DcbMessage(rd_data)
                r_msg.decode()
                logger.debug("%s: Received message %s", self.device, r_msg)
                err = self.check_error(r_msg, seq)
                if err == netlink.NLMSG_ERROR:
                    e_msg = (f'{self.device}: NLMSG_ERROR for command '
                             f'{cmd_to_name(cmd)}')
                    raise DCBErrorException(e_msg)
                if err < 0:
                    retry += 1
                else:
                    break
        except Exception:
            e_msg = f'{self.device}: Failed to get the reply for {cmd}'
            raise DCBErrorException(e_msg)
        return r_msg

    def get_dcbx(self):
        r_msg = self.send_and_receive(cmd=dcb_netlink.DCB_CMD_GDCBX,
                                      msg_type=RTM_GETDCB,
                                      attr=[])
        dcbx = r_msg.get_encoded('DCB_ATTR_DCBX')
        logger.debug("%s: DCBX mode %d 0->FW 1->OS", self.device, dcbx % 2)
        return dcbx

    def set_dcbx(self, mode):
        dcbx_data = ['DCB_ATTR_DCBX', mode]
        logger.debug("%s: Setting DCBX mode: %s", self.device, dcbx_data)
        r_msg = self.send_and_receive(cmd=dcb_netlink.DCB_CMD_SDCBX,
                                      msg_type=RTM_SETDCB,
                                      attr=[dcbx_data])
        dcbx = r_msg.get_encoded('DCB_ATTR_DCBX')
        logger.debug(
            "%s: Read DCBX mode: %d 0->FW 1->OS", self.device, dcbx % 2
        )
        return dcbx

    def get_ieee_ets(self):
        r_msg = self.send_and_receive(cmd=dcb_netlink.DCB_CMD_IEEE_GET,
                                      msg_type=RTM_GETDCB,
                                      attr=[])
        device = r_msg.get_encoded('DCB_ATTR_IFNAME')
        ieee_ets = r_msg.get_nested('DCB_ATTR_IEEE',
                                    'DCB_ATTR_IEEE_ETS')
        if ieee_ets:
            tc_tx_bw = ieee_ets['tc_tx_bw']
            tc_tsa = ieee_ets['tc_tsa']
            prio_tc = ieee_ets['prio_tc']

        else:
            return None, None, None

        logger.debug(
            "%s: Received tc_tx_bw: %s tc_tsa: %s prio_tc: %s",
            device,
            tc_tx_bw,
            tc_tsa,
            prio_tc,
        )

        return prio_tc, tc_tsa, tc_tx_bw

    def get_ieee_app_table(self):
        r_msg = self.send_and_receive(cmd=dcb_netlink.DCB_CMD_IEEE_GET,
                                      msg_type=RTM_GETDCB,
                                      attr=[])
        dcb_app_list = []
        ieee_app_table = r_msg.get_nested('DCB_ATTR_IEEE',
                                          'DCB_ATTR_IEEE_APP_TABLE')
        if ieee_app_table:
            dcb_app_list = self.get_nested_attr(ieee_app_table,
                                                'DCB_ATTR_IEEE_APP')

        appTable = DcbAppTable()
        for i in range(len(dcb_app_list)):
            selector = dcb_app_list[i]['selector']
            priority = dcb_app_list[i]['priority']
            protocol = dcb_app_list[i]['protocol']
            appTable.apps[i] = DcbApp(selector, priority, protocol)

        return appTable

    def add_nested_attr(self, attr, attr_data):
        return [attr, {'attrs': [attr_data]}]

    def get_nested_attr(self, attr_data, attr):
        nested_attr_data = attr_data['attrs']
        desired_attr_list = []
        for entry in nested_attr_data:
            if attr in entry:
                desired_attr_list.append(entry[1])
        return desired_attr_list

    def set_ieee_app(self, selector, priority, protocol):
        dcb_app = {'selector': selector,
                   'priority': priority,
                   'protocol': protocol}
        logger.debug("Adding ieee app %s", dcb_app)

        ieee_app = ['DCB_ATTR_IEEE_APP', dcb_app]
        ieee_app_table = self.add_nested_attr('DCB_ATTR_IEEE_APP_TABLE',
                                              ieee_app)
        ieee = self.add_nested_attr('DCB_ATTR_IEEE', ieee_app_table)

        self.send_and_receive(cmd=dcb_netlink.DCB_CMD_IEEE_SET,
                              msg_type=RTM_SETDCB,
                              attr=[ieee])

    def del_ieee_app(self, selector, priority, protocol):
        dcb_app = {'selector': selector,
                   'priority': priority,
                   'protocol': protocol}
        logger.debug("Deleting ieee app %s", dcb_app)
        ieee_app = ['DCB_ATTR_IEEE_APP', dcb_app]
        ieee_app_table = self.add_nested_attr('DCB_ATTR_IEEE_APP_TABLE',
                                              ieee_app)
        ieee = self.add_nested_attr('DCB_ATTR_IEEE', ieee_app_table)
        self.send_and_receive(cmd=dcb_netlink.DCB_CMD_IEEE_DEL,
                              msg_type=RTM_SETDCB,
                              attr=[ieee])


class DcbApplyConfig():
    def __init__(self):
        self.dcb_user_config = common.get_dcb_config_map()

    def show(self):
        mode = {0: 'FW Controlled', 1: 'OS Controlled'}

        for cfg in self.dcb_user_config:
            device = cfg['device']
            dcb_config = DcbConfig(device)
            dscp_map = None

            dcbx_mode = dcb_config.get_dcbx() & DCB_CAP_DCBX_HOST
            app_table = dcb_config.get_ieee_app_table()
            count = app_table.count_app_selector(
                dcb_netlink.IEEE_8021QAZ_APP_SEL_DSCP)
            if count == 0:
                trust = "pcp"
            else:
                trust = "dscp"
                dscp_map = app_table.dump(
                    dcb_netlink.IEEE_8021QAZ_APP_SEL_DSCP)

            prio_tc, tsa, tc_bw = dcb_config.get_ieee_ets()

            logger.info("-----------------------------")
            logger.info("Interface: %s", device)
            logger.info("DCBX Mode : %s", mode[dcbx_mode])
            logger.info("Trust mode: %s", trust)
            if dscp_map:
                logger.info("dscp2prio mapping: %s", dscp_map)

            if prio_tc is None:
                logger.info('Failed to get IEEE ETS')
                return
            tc2up = defaultdict(list)
            for up in range(len(prio_tc)):
                tc = prio_tc[up]
                tc2up[int(tc)].append(up)

            for tc in sorted(tc2up):
                msg = ""
                try:
                    msg = "tc: %d , tsa: " % (tc)
                except Exception:
                    pass
                try:
                    if (tsa[tc] == IEEE_8021QAZ_TSA_ETS):
                        msg += "ets, bw: %s%%" % (tc_bw[tc])
                    elif (tsa[tc] == IEEE_8021QAZ_TSA_STRICT):
                        msg += "strict"
                    elif (tsa[tc] == IEEE_8021QAZ_TSA_VENDOR):
                        msg += "vendor"
                    else:
                        msg += "unknown"
                except Exception:
                    pass

                msg += ', priority: '
                try:
                    for up in tc2up[tc]:
                        msg += f' {up} '
                except Exception:
                    pass
                if msg:
                    logger.info(msg)

    def apply(self):

        for cfg in self.dcb_user_config:
            if 'device' not in cfg:
                continue
            dcb_config = DcbConfig(cfg['device'])

            dcbx_mode = dcb_config.get_dcbx() & DCB_CAP_DCBX_HOST
            # In case of mellanox nic, set the mstconfig and do fwreset
            # If the DCBX mode is already set to FW (0), ignore
            # performing mstconfig and mstfwreset.
            if (
                'mlx' in cfg['driver'] and
                not is_dcbx_mstconfig_enabled(cfg['device'], cfg['pci_addr'])
            ):
                mstconfig(cfg['device'], cfg['pci_addr'])
                mstfwreset(cfg['device'], cfg['pci_addr'])

            # Set the mode to Firmware
            if dcbx_mode != 0:
                dcb_config.set_dcbx(mode=0)
            curr_apptable = dcb_config.get_ieee_app_table()
            add_app_table = DcbAppTable()
            user_dscp2prio = cfg['dscp2prio']
            i = 0
            for index in range(len(user_dscp2prio)):
                selector = user_dscp2prio[index]['selector']
                priority = user_dscp2prio[index]['priority']
                protocol = user_dscp2prio[index]['protocol']
                dcb_app = DcbApp(selector, priority, protocol)
                for key in curr_apptable.apps.keys():
                    if dcb_app.is_equal(curr_apptable.apps[key]):
                        logger.debug(
                            "%s: Not adding %s", cfg["device"], dcb_app.dump()
                        )
                        curr_apptable.apps.pop(key)
                        break
                else:
                    logger.debug(
                        "%s: Adding %s", cfg["device"], dcb_app.dump()
                    )
                    add_app_table.apps.update({i: dcb_app})
                    i += 1
            curr_apptable.del_app_entry(dcb_config,
                                        dcb_netlink.IEEE_8021QAZ_APP_SEL_DSCP)
            add_app_table.set_values(dcb_config)


def mstconfig(device, pci_addr):
    """Allow FW controlled mode for mellanox devices.

    :device Interface name where firmware configurations needs change
    :pci_addr pci address of the interface
    """

    logger.info("%s: Running mstconfig", device)
    try:
        processutils.execute('mstconfig', '-y', '-d', pci_addr, 'set',
                             'LLDP_NB_DCBX_P1=TRUE', 'LLDP_NB_TX_MODE_P1=2',
                             'LLDP_NB_RX_MODE_P1=2', 'LLDP_NB_DCBX_P2=TRUE',
                             'LLDP_NB_TX_MODE_P2=2', 'LLDP_NB_RX_MODE_P2=2')
    except processutils.ProcessExecutionError:
        logger.error("%s: mstconfig failed", device)
        raise


def mstfwreset(device, pci_addr):
    """mstfwreset is an utility to reset the PCI device and load new FW"""
    logger.info("%s: Running mstfwreset", device)
    try:
        processutils.execute('mstfwreset', '--device', pci_addr,
                             '--level', '3', '-y', 'r')
    except processutils.ProcessExecutionError:
        logger.error("%s: mstfwreset failed", device)
        raise


def is_dcbx_mstconfig_enabled(device, pci_addr):
    """Check if DCBX mode is enabled for a Mellanox NIC using mstconfig.

    This function verifies the required DCBX settings on the Mellanox NIC by
    querying the configuration using the mstconfig tool.

    Args:
        device (str): Interface name of the NIC.
        pci_addr (str): PCI address of the NIC.

    Returns:
        bool: True if configuration matches expected values, False otherwise.
    """
    expected_values = {
        "LLDP_NB_DCBX_P1": "True",
        "LLDP_NB_TX_MODE_P1": "ALL",
        "LLDP_NB_RX_MODE_P1": "ALL",
        "LLDP_NB_DCBX_P2": "True",
        "LLDP_NB_TX_MODE_P2": "ALL",
        "LLDP_NB_RX_MODE_P2": "ALL",
    }

    try:
        logger.info(
            "%s: Querying DCBX configuration with mstconfig", device
        )

        # Execute the mstconfig command and capture the output
        output, _ = processutils.execute(
            'mstconfig', '-d', pci_addr, 'query', *expected_values.keys()
        )

    except processutils.ProcessExecutionError as e:
        logger.error(
            "%s: Failed to query DCBX configuration: %s", device, e
        )
        return False

    # Process each key in expected_values and check if it's in the output
    for key, expected in expected_values.items():
        for line in output.splitlines():
            line = line.strip()
            if key in line:
                match = re.search(rf"{key}\s+(\S+)", line)
                if match:
                    actual = match.group(1).strip()

                    # Remove any parentheses and the content inside them
                    actual = re.sub(r'\(.*\)', '', actual).strip()

                    # Check if the actual value matches the expected value
                    if actual != expected:
                        logger.info(
                            "%s: %s does not match"
                            "Expected: %s, Found: %s",
                            device, key, expected, actual
                        )
                        return False
                    else:
                        logger.debug(
                            "%s: %s = %s is configured", device, key, actual
                        )
                        break

        else:
            logger.warning(
                "%s: %s is not configured", device, key
            )
            return False

    logger.info(
        "%s: Device is already configured.", device
    )
    return True


def cmd_to_name(cmd):
    cmds_map = {dcb_netlink.DCB_CMD_IEEE_SET: 'DCB_CMD_IEEE_SET',
                dcb_netlink.DCB_CMD_IEEE_GET: 'DCB_CMD_IEEE_GET',
                dcb_netlink.DCB_CMD_GDCBX: 'DCB_CMD_GDCBX',
                dcb_netlink.DCB_CMD_SDCBX: 'DCB_CMD_SDCBX',
                dcb_netlink.DCB_CMD_IEEE_DEL: 'DCB_CMD_IEEE_DEL'}
    return cmds_map[cmd]


def msg_type_to_name(msg_type):
    msg_type_map = {RTM_SETDCB: 'RTM_SETDCB',
                    RTM_GETDCB: 'RTM_GETDCB'}
    return msg_type_map[msg_type]


def parse_opts(argv):
    parser = argparse.ArgumentParser(
        description='Configure the DSCP settings for the interfaces using'
        ' a YAML config file format.')

    parser.add_argument(
        '-d', '--debug',
        dest="debug",
        action='store_true',
        help="Print debugging output.",
        required=False)

    parser.add_argument(
        '-v', '--verbose',
        dest="verbose",
        action='store_true',
        help="Print verbose output.",
        required=False)

    parser.add_argument(
        '-s', '--show',
        dest="show",
        action='store_true',
        help="Print the DCB configurations.",
        required=False)

    parser.add_argument('-c', '--config-file', metavar='CONFIG_FILE',
                        help="""path to the configuration file.""",
                        required=False)

    opts = parser.parse_args(argv[1:])

    return opts


def parse_config(user_config_file):
    # Read config file containing network configs to apply
    if os.path.exists(user_config_file):
        try:
            with open(user_config_file) as cf:
                iface_array = yaml.safe_load(cf.read()).get("dcb_config")
                logger.debug("dcb_config: %s", iface_array)
        except IOError:
            logger.error("Error reading file: %s", user_config_file)
            return 1
    else:
        logger.error("No config file exists at: %s", user_config_file)
        return 1

    # Validate the configurations for schematic errors
    validation_errors = validator.validate_config(iface_array)
    if validation_errors:
        logger.error('\n'.join(validation_errors))
        return 1

    # Get the DCB Map and clear all the dscp2prio map for all
    # previously configured interfaces. Add the dscp2prio entries
    # from the new configuration and write the contents to
    # DCB Config File
    dcb_map = common.get_empty_dcb_map()
    for iface_json in iface_array:
        obj = objects.object_from_json(iface_json)
        if isinstance(obj, objects.Dcb):
            common.add_dcb_entry(dcb_map, obj)
        else:
            e_msg = 'Only dcb objects are handled'
            raise DCBErrorException(e_msg)
    common.write_dcb_map(dcb_map)


def main(argv=sys.argv):
    opts = parse_opts(argv)
    logger = common.configure_logger(log_file=True)
    common.logger_level(logger, opts.verbose, opts.debug)
    common.set_noop(False)

    if opts.config_file:
        # Validate and parse the user configurations.
        parse_config(opts.config_file)

    dcb_apply = DcbApplyConfig()
    if opts.show:
        # Enable verbose logs to display the output
        common.logger_level(logger, True, opts.debug)
        dcb_apply.show()
    else:
        # Apply the new DCB configuration
        dcb_apply.apply()
        utils.configure_dcb_config_service()
        common.logger_level(logger, True, opts.debug)
        dcb_apply.show()


if __name__ == '__main__':
    sys.exit(main(sys.argv))
