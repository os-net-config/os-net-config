# -*- coding: utf-8 -*-

# Copyright 2014 Red Hat, Inc.
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

#
# Common functions and variables meant to be shared across various modules
# As opposed to utils, this is meant to be imported from anywhere. We can't
# import anything from os_net_config here.

import logging
import logging.handlers
import os
from oslo_concurrency import processutils
import sys
import time
import traceback
import yaml

# File to contain the DPDK mapped nics, as nic name will not be available after
# binding driver, which is required for correct nic numbering.
# Format of the file (list mapped nic's details):
#   -
#     name: eth1
#     pci_address: 0000:02:00.0
#     mac_address: 01:02:03:04:05:06
#     driver: vfio-pci
DPDK_MAPPING_FILE = '/var/lib/os-net-config/dpdk_mapping.yaml'

# File to contain the list of SR-IOV PF, VF and their configurations
# Format of the file shall be
# - device_type: pf
#   name: <pf name>
#   numvfs: <number of VFs>
#   drivers_autprobe: true/false
#   promisc: "on"/"off"
# - device_type: vf
#   device:
#      name: <pf name>
#      vfid: <VF id>
#   name: <vf name>
#   vlan_id: <vlan>
#   qos: <qos>
#   spoofcheck: "on"/"off"
#   trust: "on"/"off"
#   state: "auto"/"enable"/"disable"
#   macaddr: <mac address>
#   promisc: "on"/"off"
SRIOV_CONFIG_FILE = '/var/lib/os-net-config/sriov_config.yaml'

# File to contain the list of DCB configurations
# Format of the file shall be
# - name: <pf name>
#   dscp2prio:
#       - protocol: 44
#         selector: 5
#         priority: 6
#       - protocol: 42
#         selector: 5
#         priority: 3

DCB_CONFIG_FILE = '/var/lib/os-net-config/dcb_config.yaml'

_SYS_BUS_PCI_DEV = '/sys/bus/pci/devices'
SYS_CLASS_NET = '/sys/class/net'
_LOG_FILE = '/var/log/os-net-config.log'
MLNX_VENDOR_ID = "0x15b3"
MAC_TABLE_SIZE = 50000

logger = logging.getLogger(__name__)


class OvsDpdkBindException(ValueError):
    pass


class SriovVfNotFoundException(ValueError):
    pass


def set_noop(value):
    global noop
    noop = value


def get_noop():
    global noop
    return noop


def log_exceptions(type, value, tb):
    logger.exception(''.join(traceback.format_exception(
        type, value, tb)))
    # calls default excepthook
    sys.__excepthook__(type, value, tb)


def configure_logger(log_file=False, verbose=False, debug=False):
    LOG_FORMAT = ('%(asctime)s.%(msecs)03d %(levelname)s '
                  '%(name)s.%(funcName)s %(message)s')
    DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
    logger = logging.getLogger("os_net_config")
    logger.handlers.clear()
    logger_level(logger, verbose, debug)
    logger.propagate = True
    formatter = logging.Formatter(fmt=LOG_FORMAT, datefmt=DATE_FORMAT)
    if log_file:
        file_handler = logging.handlers.RotatingFileHandler(
            _LOG_FILE, maxBytes=10485760, backupCount=7
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    # Install exception handler
    sys.excepthook = log_exceptions
    return logger


def logger_level(logger, verbose=False, debug=False):
    log_level = logging.WARN
    if debug:
        log_level = logging.DEBUG
    elif verbose:
        log_level = logging.INFO
    logger.setLevel(log_level)


def get_dev_path(ifname, path=None):
    if not path:
        path = ""
    elif path.startswith("_"):
        path = path[1:]
    else:
        path = f"device/{path}"
    return os.path.join(SYS_CLASS_NET, ifname, path)


def get_pci_dev_path(pci_address, path=""):
    if path.startswith("_"):
        path = path[1:]
    return os.path.join(_SYS_BUS_PCI_DEV, pci_address, path)


def get_vendor_id(ifname):
    try:
        with open(get_dev_path(ifname, "vendor"), 'r') as f:
            out = f.read().strip()
        return out
    except IOError:
        return


def get_device_id(ifname):
    try:
        with open(get_dev_path(ifname, 'device'), 'r') as f:
            out = f.read().strip()
        return out
    except IOError:
        return


def get_file_data(filename):
    if not os.path.exists(filename):
        return ''
    try:
        with open(filename, 'r') as f:
            return f.read()
    except IOError:
        logger.error("Error reading file: %s", filename)
        return ''


def write_yaml_config(filepath, data):
    if get_noop():
        logger.info("Writing file %s with content %s", filepath, data)
        return
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w') as f:
        yaml.safe_dump(data, f, default_flow_style=False)


def update_dcb_map(device, pci_addr, driver, noop, dscp2prio=None):
    if not noop:
        dcb_map = get_dcb_config_map()
        for item in dcb_map:
            if item['pci_addr'] == pci_addr:
                item['device'] = device
                item['driver'] = driver
                item['dscp2prio'] = dscp2prio
                break
        else:
            new_item = {}
            new_item['pci_addr'] = pci_addr
            new_item['driver'] = driver
            new_item['device'] = device
            new_item['dscp2prio'] = dscp2prio
            dcb_map.append(new_item)

        write_yaml_config(DCB_CONFIG_FILE, dcb_map)


def write_dcb_map(dcb_map):
    write_yaml_config(DCB_CONFIG_FILE, dcb_map)


def get_dcb_config_map():
    contents = get_file_data(DCB_CONFIG_FILE)
    dcb_config_map = yaml.safe_load(contents) if contents else []
    return dcb_config_map


def get_empty_dcb_map():
    contents = get_file_data(DCB_CONFIG_FILE)
    dcb_config_map = yaml.safe_load(contents) if contents else []
    for entry in dcb_config_map:
        entry['dscp2prio'] = []
    return dcb_config_map


def add_dcb_entry(dcb_config_map, data):
    for entry in dcb_config_map:
        if entry['pci_addr'] == data.pci_addr:
            entry['dscp2prio'] = data.dscp2prio
            entry['device'] = data.device
            entry['driver'] = data.driver
            break
    else:
        new_entry = {}
        new_entry['device'] = data.device
        new_entry['pci_addr'] = data.pci_addr
        new_entry['driver'] = data.driver
        new_entry['dscp2prio'] = data.dscp2prio

        dcb_config_map.append(new_entry)
    return dcb_config_map


def reset_dcb_map():
    dcb_map = get_empty_dcb_map()
    if dcb_map != []:
        write_dcb_map(dcb_map)


def get_sriov_map(pf_name=None):
    contents = get_file_data(SRIOV_CONFIG_FILE)
    sriov_map = yaml.safe_load(contents) if contents else []
    if len(sriov_map) and pf_name:
        return [pf for pf in sriov_map if pf['name'] == pf_name]
    return sriov_map


def get_dpdk_map():
    contents = get_file_data(DPDK_MAPPING_FILE)
    dpdk_map = yaml.safe_load(contents) if contents else []
    return dpdk_map


def get_sriov_pfs():
    sriov_map = get_sriov_map()
    return [pf for pf in sriov_map if pf["device_type"] == "pf"]


def get_sriov_pf_names():
    sriov_map = get_sriov_map()
    return [pf['name'] for pf in sriov_map if pf["device_type"] == "pf"]


def get_dpdk_iface_names():
    contents = get_file_data(DPDK_MAPPING_FILE)
    dpdk_map = yaml.safe_load(contents) if contents else []
    iface_names = [item['name'] for item in dpdk_map]
    return iface_names


def _get_dpdk_mac_address(name):
    contents = get_file_data(DPDK_MAPPING_FILE)
    dpdk_map = yaml.safe_load(contents) if contents else []
    for item in dpdk_map:
        if item['name'] == name:
            return item['mac_address']


def interface_mac(name):
    try:  # If the iface is part of a Linux bond, the real MAC is only here.
        with open(get_dev_path(name, '_bonding_slave/perm_hwaddr'),
                  'r') as f:
            return f.read().rstrip()
    except IOError:
        pass  # Iface is not part of a bond, continue

    try:
        with open(get_dev_path(name, '_address'), 'r') as f:
            return f.read().rstrip()
    except IOError:
        # If the interface is bound to a DPDK driver, get the mac address from
        # the DPDK mapping file as /sys files will be removed after binding.
        dpdk_mac_address = _get_dpdk_mac_address(name)
        if dpdk_mac_address:
            return dpdk_mac_address
        sriov_mac_address = _get_sriov_mac_address(name)
        if sriov_mac_address:
            return sriov_mac_address
        logger.error("Unable to read mac address: %s" % name)
        raise


def get_pci_device_driver(pci_addr):
    """Fetch the driver attached to the device

    :param pci_addr: PCI address of the the device
    :returns: driver attached to the PCI device
    """
    if get_noop():
        logger.info("%s: Fetching the PCI device driver", pci_addr)
        return
    driver_path = get_pci_dev_path(pci_addr, 'driver')
    try:
        driver = os.readlink(driver_path)
        driver = os.path.basename(driver)
        logger.info("%s: Bound with %s", pci_addr, driver)
        return driver
    except OSError as exp:
        logger.info(
            "%s: Not bound with any driver. Err %s", pci_addr, exp
        )
        return None


def is_mellanox_interface(ifname):
    vendor_id = get_vendor_id(ifname)
    return vendor_id == MLNX_VENDOR_ID


def is_vf(pci_address):

    # If DPDK drivers are bound on a VF, then the path common.SYS_CLASS_NET
    # wouldn't exist. Instead we look for the path
    # /sys/bus/pci/devices/<PCI addr>/physfn to understand if the device
    # is actually a VF. This path could be used by VFs not bound with
    # DPDK drivers as well

    vf_path_check = _SYS_BUS_PCI_DEV + '/%s/physfn' % pci_address
    is_sriov_vf = os.path.isdir(vf_path_check)
    return is_sriov_vf


def get_pci_address(name):
    """Fetch the PCI address of the interface

    Fetch the PCI address of the device from the /sys/class/net
    subsystem when the interface is bound with the ethernet drivers.
    If the device is bound with vfio-pci, the pci address is fetched
    from the dpdk map.
    :param name: name of the interface. For vfs the name could
        be written in the format f"sriov:{pf_name}:{vfid}"
    :returns: Return the PCI address
    """
    vfid = None
    device = name.split(":")
    ifname = device[0]
    if len(device) == 3 and ifname == "sriov":
        ifname = device[1]
        vfid = device[2]

    if vfid:
        dev_path = get_dev_path(ifname, f'virtfn{vfid}')
    else:
        dev_path = get_dev_path(ifname, '_device')
    try:
        pci_addr = os.readlink(dev_path)
        pci_addr = os.path.basename(pci_addr)
    except OSError as exc:
        # for VFs the PCI address could always be identified from sysfs
        # using the PF device and the VF id even if the VF is bound with
        # DPDK driver. So there is no ned to run through the DPDK map
        # for retrieving the corresponding pci address
        if vfid:
            msg = f"{ifname}:{vfid} Unable to get pci address"
            raise SriovVfNotFoundException(msg)
        logger.info(
            "%s: Unable to get pci address from sysfs. Err: %s", ifname, exc
        )
        pci_addr = get_dpdk_pci_address(ifname)

    logger.info("%s: pci address is %s", ifname, pci_addr)
    return pci_addr


def get_dpdk_pci_address(ifname):
    # In case of DPDK devices, the pci address could be fetched
    # before performing the driverctl override.
    # basename $(readlink /sys/class/net/<ifname>/device)
    # After setting the override, the pci address could be read back
    # from the dpdk map.
    logger.info("%s: Fetch pci address from dpdk map", ifname)
    dpdk_map = get_dpdk_map()
    for dpdk_nic in dpdk_map:
        if dpdk_nic['name'] == ifname:
            return dpdk_nic['pci_address']


def get_sriov_pci_address(name):
    sriov_map = get_sriov_map(pf_name=name)
    if sriov_map:
        return sriov_map[0].get('pci_address', None)


def _get_sriov_mac_address(iface_name):
    """Fetch the Mac address from the sriov_map."""
    sriov_map = get_sriov_map(pf_name=iface_name)
    if sriov_map:
        return sriov_map[0].get('mac_address', None)


def is_pf_attached_to_guest(iface_name):
    driver = None
    pci_addr = get_sriov_pci_address(iface_name)
    if pci_addr:
        driver = get_pci_device_driver(pci_addr)
    if driver == 'vfio-pci':
        return True
    return False


def is_vf_by_name(interface_name, check_mapping_file=False):
    vf_path_check = get_dev_path(interface_name, 'physfn')
    is_sriov_vf = os.path.isdir(vf_path_check)
    if not is_sriov_vf and check_mapping_file:
        sriov_map = get_sriov_map()
        for item in sriov_map:
            if (item['name'] == interface_name and
                    item['device_type'] == 'vf'):
                is_sriov_vf = True
    return is_sriov_vf


def get_default_vf_driver(pf_name, vfid):
    modalias_path = get_dev_path(pf_name, f"virtfn{vfid}/modalias")
    try:
        with open(modalias_path) as f:
            alias = f.read().strip()
        cmd = ["modprobe", "-R", alias]
        out, err = processutils.execute(*cmd)
        kernel_driver = out.strip()
        logger.info(
            "%s-%s: default vf driver is %s", pf_name, vfid, kernel_driver
        )
        return kernel_driver
    except (OSError, processutils.ProcessExecutionError) as e:
        logger.error(
            "%s-%s: failed to get default vf driver: %s", pf_name, vfid, e
        )
        return None


def wait_for_vf_driver_binding(pf, vfs, req_driver):
    """Wait for the VF to be bound with the required driver

    If the standard device driver is bound with the VF, then wait until the
    sysfs paths corresponding to the network interface is available.
    For vfio-pci driver, wait until the device is bound with the driver.
    :params pf: PF device name
    :params vfs: list of VF that are bound with req_driver
    :parans req_driver: The driver which shall be bound with the device
    """
    for vf in vfs:
        driver = None
        pci_address = get_pci_address(f"sriov:{pf}:{vf}")
        for i in range(30):
            driver = get_pci_device_driver(pci_address)
            if driver == req_driver:
                logger.info("%s-%s: verified binding with %s", pf, vf, driver)
                break
            time.sleep(1)
        else:
            logger.error(
                "%s-%s: bound with %s instead of %s",
                pf,
                vf,
                driver,
                req_driver,
            )
        if driver != "vfio-pci":
            vf_path = get_dev_path(pf, f"virtfn{vf}/net")
            for i in range(30):
                if os.path.exists(vf_path):
                    break
                time.sleep(1)
            else:
                logger.warning(
                    "%s-%s: device path %s is not available yet",
                    pf,
                    vf,
                    vf_path,
                )


def set_driverctl_override(pci_address, driver):
    if driver is None:
        logger.info("%s: Driver override is not required.", pci_address)
        return False
    iface_driver = get_pci_device_driver(pci_address)
    if iface_driver == driver:
        logger.info("%s: %s is already bound", pci_address, driver)
        return False
    try:
        if is_vf(pci_address):
            cmd = [
                "driverctl",
                "--nosave",
                "set-override",
                pci_address,
                driver,
            ]
        else:
            cmd = ["driverctl", "set-override", pci_address, driver]
        logger.info(
            "%s: Binding with %s\n%s", pci_address, driver, " ".join(cmd)
        )
        out, err = processutils.execute(*cmd)
        if err:
            msg = f"{pci_address}: Failed to bind dpdk interface. err - {err}"
            raise OvsDpdkBindException(msg)
    except processutils.ProcessExecutionError:
        msg = f"{pci_address}: Failed to bind interface with dpdk"
        raise OvsDpdkBindException(msg)
    return err


def list_kmods(mods: list) -> list:
    """Listing Kernel Modules

    Checks in currently loaded modules for a list
    of modules and returns the ones that are not loaded
    """
    try:
        stdout, stderr = processutils.execute('lsmod')
    except processutils.ProcessExecutionError as exc:
        logger.error("Failed to get lsmod: %s", exc)
        raise
    modules = set([line.split()[0] for line in stdout.strip().split('\n')])
    return list(set(mods) - set(modules))


def load_kmods(mods: list):
    """Loading Kernel Modules

    Loads modules from list that are not already loaded
    """
    needed = list_kmods(mods)
    for mod in needed:
        try:
            stdout, stderr = processutils.execute('modprobe', mod)
        except processutils.ProcessExecutionError as exc:
            logger.error("Failed to modprobe %s: %s", mod, exc)
            raise


def restorecon(path: str):
    """Executes restorecon on a path"""
    logger.info("Restoring selinux context on %s", path)
    try:
        stdout, stderr = processutils.execute('restorecon', '-R', '-F', '-v',
                                              path)
    except processutils.ProcessExecutionError as exc:
        logger.error("Failed to restorecon on %s: %s", path, exc)
        raise
    logger.debug("Restorecon completed: %s", stdout)
