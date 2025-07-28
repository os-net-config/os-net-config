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


import argparse
from enum import IntEnum
import importlib
import json
import os
import sys
import yaml

from os_net_config import common
from os_net_config import objects
from os_net_config import utils
from os_net_config import validator
from os_net_config import version


class ExitCode(IntEnum):
    """Exit codes used by os-net-config.

    These codes indicate the result of configuration operations:
    - SUCCESS: Configuration completed successfully
    - ERROR: Configuration failed due to an error
    Below values are returned when --detailed_exit_code is enabled in cli
    - FILES_CHANGED: Configuration successful and files were modified
    """
    SUCCESS = 0          # Configuration successful
    ERROR = 1            # Configuration failed
    FILES_CHANGED = 2    # Configuration successful, files were modified


logger = common.configure_logger()

_SYSTEM_CTL_CONFIG_FILE = '/etc/sysctl.d/os-net-sysctl.conf'
_PROVIDERS = {
    'ifcfg': 'IfcfgNetConfig',
    'eni': 'ENINetConfig',
    'iproute': 'IprouteNetConfig',
    'nmstate': 'NmstateNetConfig',
}


def parse_opts(argv):
    parser = argparse.ArgumentParser(
        description='Configure host network interfaces using a JSON'
        ' config file format.')
    parser.add_argument('-c', '--config-file', metavar='CONFIG_FILE',
                        help="""path to the configuration file.""",
                        default='/etc/os-net-config/config.yaml')
    parser.add_argument('-m', '--mapping-file', metavar='MAPPING_FILE',
                        help="""path to the interface mapping file.""",
                        default='/etc/os-net-config/mapping.yaml')
    parser.add_argument('-i', '--interfaces', metavar='INTERFACES',
                        help="""Identify the real interface for a nic name. """
                        """If a real name is given, it is returned if live. """
                        """If no value is given, display full NIC mapping. """
                        """Exit after printing, ignoring other parameters. """,
                        nargs='*', default=None)
    parser.add_argument('-r', '--root-dir', metavar='ROOT_DIR',
                        help="""The root directory of the filesystem.""",
                        default='')
    parser.add_argument('-p', '--provider', metavar='PROVIDER',
                        help="""The provider to use. """
                        """One of: ifcfg, eni, nmstate, iproute.""",
                        choices=_PROVIDERS.keys(),
                        default=None)
    parser.add_argument('--purge-provider', metavar='PURGE_PROVIDER',
                        help="""Cleans the network configurations created """
                        """by the specified provider. There shall be no """
                        """change in the input network config.yaml during """
                        """the purge operation. One of: ifcfg, nmstate.""",
                        choices=_PROVIDERS.keys(),
                        default=None)
    parser.add_argument('--detailed-exit-codes',
                        action='store_true',
                        help="""Enable detailed exit codes. """
                        """If enabled an exit code of FILES_CHANGED means """
                        """that files were modified. """
                        """Disabled by default.""",
                        default=False)

    parser.add_argument(
        '--exit-on-validation-errors',
        action='store_true',
        help="Exit with an error if configuration file validation fails. "
             "Without this option, just log a warning and continue.",
        default=False)

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

    parser.add_argument('--version', action='version',
                        version=version.version_info.version_string())
    parser.add_argument(
        '--noop',
        dest="noop",
        action='store_true',
        help="Return the configuration commands, without applying them.",
        required=False)

    parser.add_argument(
        '--no-activate',
        dest="no_activate",
        action='store_true',
        help="Install the configuration but don't start/stop interfaces.",
        required=False)

    parser.add_argument(
        '--cleanup',
        dest="cleanup",
        action='store_true',
        help="Cleanup unconfigured interfaces.",
        required=False)

    parser.add_argument(
        '--persist-mapping',
        dest="persist_mapping",
        action='store_true',
        help="Make aliases defined in the mapping file permanent "
             "(WARNING, permanently renames nics).",
        required=False)

    opts = parser.parse_args(argv[1:])

    return opts


def _is_sriovpf_obj_found(obj):
    configure_sriov = False
    if isinstance(obj, objects.SriovPF):
        configure_sriov = True
    elif hasattr(obj, 'members') and obj.members is not None:
        for member in obj.members:
            if isinstance(member, objects.SriovPF):
                configure_sriov = True
                break
            else:
                configure_sriov = _is_sriovpf_obj_found(member)
    return configure_sriov


def disable_ipv6_for_netdevs(net_devices):
    sysctl_conf = ""
    for net_device in net_devices:
        sysctl_conf += "net.ipv6.conf.%s.disable_ipv6 = 1\n" % net_device
    utils.write_config(_SYSTEM_CTL_CONFIG_FILE, sysctl_conf)


def get_sriovpf_member_of_bond_ovs_port(obj):
    net_devs_list = []
    if isinstance(obj, objects.OvsBridge):
        for member in obj.members:
            if isinstance(member, objects.LinuxBond):
                for child_member in member.members:
                    if isinstance(child_member, objects.SriovPF):
                        if child_member.link_mode == 'switchdev':
                            net_devs_list.append(child_member.name)
    return net_devs_list


def load_provider(name, noop, root_dir):
    mod = importlib.import_module(f'os_net_config.impl_{name}')
    provider_class = getattr(mod, _PROVIDERS[name])
    return provider_class(noop=noop, root_dir=root_dir)


def is_nmstate_available():
    try:
        import libnmstate
        from packaging.version import Version
        if Version(libnmstate.__version__) > Version('2.2.32'):
            logger.info(
                "libnmstate version %s > 2.2.32. Supports nmstate provider",
                libnmstate.__version__
            )
            return True
    except ImportError:
        logger.info("Could not find libnmstate packages")
        return False

    logger.info(
        "libnmstate version %s is incompatible for minimum support. "
        "Need 2.2.32",
        libnmstate.__version__,
    )
    return False


def main(argv=sys.argv, main_logger=None):
    opts = parse_opts(argv)

    common.set_noop(opts.noop)

    if not main_logger:
        main_logger = common.configure_logger(log_file=not opts.noop)
    common.logger_level(main_logger, opts.verbose, opts.debug)
    main_logger.info("Using config file at: %s", opts.config_file)
    iface_array = []

    # Read the interface mapping file, if it exists
    # This allows you to override the default network naming abstraction
    # mappings by specifying a specific nicN->name or nicN->MAC mapping
    if os.path.exists(opts.mapping_file):
        main_logger.info("Using mapping file at: %s", opts.mapping_file)
        with open(opts.mapping_file) as cf:
            iface_map = yaml.safe_load(cf.read())
            iface_mapping = iface_map.get("interface_mapping")
            main_logger.debug("interface_mapping: %s", iface_mapping)
            persist_mapping = opts.persist_mapping
            main_logger.debug("persist_mapping: %s", persist_mapping)
    else:
        main_logger.info("Not using any mapping file.")
        iface_mapping = None
        persist_mapping = False

    # If --interfaces is specified, either return the real name of the
    # interfaces specified, or return the map of all nic abstractions/names.
    if opts.interfaces is not None:
        reported_nics = {}
        mapped_nics = objects.mapped_nics(iface_mapping)
        retval = ExitCode.SUCCESS
        if len(opts.interfaces) > 0:
            for requested_nic in opts.interfaces:
                found = False
                # Check to see if requested iface is a mapped NIC name.
                if requested_nic in mapped_nics:
                    reported_nics[requested_nic] = mapped_nics[requested_nic]
                    found = True
                # Check to see if the requested iface is a real NIC name
                if requested_nic in mapped_nics.values():
                    if found is True:  # Name matches alias and real NIC
                        # (return the mapped NIC, but warn of overlap).
                        main_logger.warning(
                            "%s overlaps with real NIC name.", requested_nic
                        )
                    else:
                        reported_nics[requested_nic] = requested_nic
                        found = True
                if not found:
                    retval = ExitCode.ERROR
            if reported_nics:
                main_logger.debug(
                    "Interface mapping requested for interface: %s",
                    reported_nics.keys(),
                )
        else:
            main_logger.debug("Interface mapping requested for all interfaces")
            reported_nics = mapped_nics
        # Return the report on the mapped NICs. If all NICs were found, exit
        # cleanly, otherwise exit with status ERROR.
        main_logger.debug("Interface report requested, exiting after report.")
        print(json.dumps(reported_nics))
        return retval
    try:
        iface_array = get_iface_config(
            "network_config",
            opts.config_file,
            iface_mapping,
            persist_mapping,
            strict_validate=opts.exit_on_validation_errors,
        )
    except objects.InvalidConfigException as e:
        main_logger.error("Schema validation failed for network_config\n%s", e)
        return ExitCode.ERROR

    if not iface_array:
        return ExitCode.ERROR

    # Reset the DCB Config during rerun.
    # This is required to apply the new values and clear the old ones
    if utils.is_dcb_config_required():
        common.reset_dcb_map()

    if opts.purge_provider:
        purge_ret = unconfig_provider(
            opts.purge_provider,
            iface_array,
            opts.root_dir,
            opts.noop
        )
        if purge_ret != ExitCode.SUCCESS:
            main_logger.error(
                "Failed to purge %s provider", opts.purge_provider
            )
            return purge_ret

    if not opts.provider:
        ifcfg_path = f'{opts.root_dir}/etc/sysconfig/network-scripts/'
        if is_nmstate_available():
            opts.provider = "nmstate"
        elif os.path.exists(ifcfg_path):
            opts.provider = "ifcfg"
        elif os.path.exists('%s/etc/network/' % opts.root_dir):
            opts.provider = "eni"
        else:
            main_logger.error("Unable to set provider for this operating "
                              "system.")
            return ExitCode.ERROR

    try:
        logger.info("%s: Applying network_config section", opts.provider)
        ret_code = config_provider(
            opts.provider,
            "network_config",
            iface_array,
            opts.root_dir,
            opts.noop,
            opts.no_activate,
            opts.cleanup,
        )
    except Exception as e:
        logger.error(
            "%s: *** Failed to apply network_config section ***\n%s",
            opts.provider,
            e
        )
        ret_code = ExitCode.ERROR

    if utils.is_dcb_config_required():
        # Apply the DCB Config
        try:
            from os_net_config import dcb_config
        except ImportError as e:
            logger.error("cannot apply DCB configuration: %s", e)
            return ExitCode.ERROR

        utils.configure_dcb_config_service()
        dcb_apply = dcb_config.DcbApplyConfig()
        dcb_apply.apply()

    if opts.detailed_exit_codes or ret_code == ExitCode.ERROR:
        return ret_code
    else:
        return ExitCode.SUCCESS


def unconfig_provider(provider_name,
                      iface_array,
                      root_dir,
                      noop,
                      ):
    """Remove network configurations created by the specified provider

     :param provider_name: Name of provider to purge (ifcfg, nmstate, etc.)
     :param iface_array: List of interface configurations
     :param root_dir: Root directory for filesystem operations
     :param noop: If True, only show what would be done
     :returns: ExitCode.SUCCESS on success, ExitCode.ERROR on error
     """
    logger.info("%s: Performing unconfig", provider_name)
    try:
        purge_provider = load_provider(provider_name, noop,
                                       root_dir)
    except ImportError as e:
        logger.error(
            "%s: cannot load purge provider, error %s", provider_name, e
        )
        return ExitCode.ERROR

    for iface_json in iface_array:
        try:
            obj = objects.object_from_json(iface_json)
        except common.SriovVfNotFoundException:
            continue
        purge_provider.del_object(obj)

    purge_provider.destroy()

    logger.info("%s: Completed unconfig", provider_name)
    return ExitCode.SUCCESS


def config_provider(provider_name,
                    config_name,
                    iface_config,
                    root_dir,
                    noop,
                    no_activate,
                    cleanup,
                    ):
    """Configure network interfaces using the specified provider

    :param provider_name: Name of provider(ifcfg, nmstate, eni, iproute)
    :param config_name: Name of configuration section being processed
    :param iface_config: List of interface configurations to apply
    :param root_dir: Root directory for filesystem operations
    :param noop: If True, only show what would be done without applying
    :param no_activate: If True, install config but don't start/stop
        interfaces
    :param cleanup: If True, cleanup unconfigured interfaces
    :returns: ExitCode

    """
    configure_sriov = False
    files_changed = {}
    pf_files_changed = []
    sriovpf_bond_ovs_ports = []
    logger.info("%s: Configuring %s", provider_name, config_name)
    try:
        provider = load_provider(provider_name, noop, root_dir)
    except ImportError as e:
        logger.error("%s: cannot load provider, error %s", provider_name, e)
        return ExitCode.ERROR

    # Look for the presence of SriovPF types in the first parse of the json
    # if SriovPFs exists then PF devices needs to be configured so that the VF
    # devices are created.
    # The VFs will not be available now and an exception
    # SriovVfNotFoundException will be raised while fetching the device name.
    # After the first parse the SR-IOV PF devices would be configured and the
    # VF devices would be created.
    # In the second parse, all other objects shall be added
    try:
        for iface_json in iface_config:
            try:
                obj = objects.object_from_json(iface_json)
            except common.SriovVfNotFoundException:
                continue

            if _is_sriovpf_obj_found(obj):
                configure_sriov = True
                provider.add_object(obj)
                # Look for the presence of SriovPF as members of LinuxBond
                # and that LinuxBond is member of OvsBridge
                sriovpf_bond_ovs_ports.extend(
                    get_sriovpf_member_of_bond_ovs_port(obj))

        # After reboot, shared_block for pf interface in switchdev mode will be
        # missing in case IPv6 is enabled on the slaves of the bond and that
        # bond is an ovs port. This is due to the fact that OVS assumes another
        # entity manages the slaves.
        # So as a workaround for that case we are disabling IPv6 over pfs so
        # that OVS creates the shared_blocks ingress
        if sriovpf_bond_ovs_ports:
            disable_ipv6_for_netdevs(sriovpf_bond_ovs_ports)

        # Apply the ifcfgs for PFs now, so that NM_CONTROLLED=no is applied
        # for each of the PFs before configuring the numvfs for the PF device.
        # This step allows the network manager to unmanage the created VFs.
        # In the second parse, when these ifcfgs for PFs are encountered,
        # os-net-config skips the ifup <ifcfg-pfs>, since the ifcfgs for PFs
        # wouldn't have changed.
        if configure_sriov:
            # Skip cleanup while applying PF configuration
            pf_files_changed = provider.apply(cleanup=False,
                                              activate=not no_activate,
                                              config_rules_dns=False)

            if provider_name == "ifcfg" and not noop:
                restart_ovs = bool(sriovpf_bond_ovs_ports)
                # Avoid ovs restart for os-net-config re-runs, which will
                # dirupt the offload configuration
                if os.path.exists(utils._SRIOV_CONFIG_SERVICE_FILE):
                    restart_ovs = False

                utils.configure_sriov_pfs(
                    execution_from_cli=True,
                    restart_openvswitch=restart_ovs)

        for iface_json in iface_config:
            # All sriov_pfs at top level or at any member level will be
            # ignored and all other objects are parsed will be added here.
            # The VFs are expected to be available now and an exception
            # SriovVfNotFoundException shall be raised if not available.
            try:
                obj = objects.object_from_json(iface_json)
            except common.SriovVfNotFoundException:
                if not noop:
                    raise

            if not _is_sriovpf_obj_found(obj):
                provider.add_object(obj)

        if provider_name == "ifcfg" and configure_sriov and not noop:
            utils.configure_sriov_vfs()

        files_changed = provider.apply(cleanup=cleanup,
                                       activate=not no_activate)
        logger.info(
            "%s: Successfully configured %s", provider_name, config_name
        )

    except Exception as e:
        logger.error(
            "%s: ***Failed to configure %s ***\n%s",
            provider_name,
            config_name,
            e
        )
        return ExitCode.ERROR

    if configure_sriov:
        files_changed.update(pf_files_changed)
    if noop:
        for location, data in files_changed.items():
            print("File:", location)
            print()
            print(data)
            print("----")
    if len(files_changed) > 0:
        return ExitCode.FILES_CHANGED
    return ExitCode.SUCCESS


def get_iface_config(
        config_name,
        config_file,
        iface_map,
        persist_map,
        strict_validate=False):
    logger.info("Reading %s for %s section", config_file, config_name)
    # Read config file containing network configs to apply
    if os.path.exists(config_file):
        try:
            with open(config_file) as cf:
                iface_array = yaml.safe_load(cf.read()).get(config_name)
                common.print_config(iface_array, config_name)
        except IOError:
            logger.error("Error reading file: %s", config_file)
            return []
        except (yaml.scanner.ScannerError, yaml.parser.ParserError) as e:
            logger.error("Invalid YAML in config file %s: %s", config_file, e)
            return []
    else:
        logger.error("No config file exists at: %s", config_file)
        return []

    if not isinstance(iface_array, list):
        logger.error(
            "No interfaces defined in config: %s", config_file
        )
        return []

    for iface_json in iface_array:
        if iface_json.get('type') != 'route_table':
            iface_json.update({'nic_mapping': iface_map})
            iface_json.update({'persist_mapping': persist_map})

    validation_errors = validator.validate_config(iface_array)
    if validation_errors:
        if strict_validate:
            for e in validation_errors:
                logger.error(e)
            msg = "\n".join(validation_errors)
            raise objects.InvalidConfigException(msg)
        else:
            for e in validation_errors:
                logger.warning(e)
    return iface_array


if __name__ == '__main__':
    sys.exit(main(sys.argv, main_logger=logger))
