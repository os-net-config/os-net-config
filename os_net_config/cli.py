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
import importlib
import json
import os
import sys
import traceback
import yaml

from os_net_config import common
from os_net_config.exit_codes import ExitCode
from os_net_config.exit_codes import get_exit_code
from os_net_config.exit_codes import has_failures
from os_net_config import objects
from os_net_config import utils
from os_net_config import validator
from os_net_config import version


logger = common.configure_logger()

_SYSTEM_CTL_CONFIG_FILE = '/etc/sysctl.d/os-net-sysctl.conf'
_PROVIDERS = {
    'ifcfg': 'IfcfgNetConfig',
    'eni': 'ENINetConfig',
    'iproute': 'IprouteNetConfig',
    'nmstate': 'NmstateNetConfig',
}

__all__ = ['ExitCode', 'get_exit_code', 'has_failures']


def parse_opts(argv):
    parser = argparse.ArgumentParser(
        description='Configure host network interfaces using a JSON'
        ' config file format.')
    parser.add_argument(
        '-c', '--config-file',
        metavar='CONFIG_FILE',
        help="""path to the configuration file.""",
        default='/etc/os-net-config/config.yaml')
    parser.add_argument(
        '-m', '--mapping-file',
        metavar='MAPPING_FILE',
        help="""path to the interface mapping file.""",
        default='/etc/os-net-config/mapping.yaml')
    parser.add_argument(
        '-i', '--interfaces',
        metavar='INTERFACES',
        help="""Identify the real interface for a nic name. If a real name """
        """is given, it is returned if live. If no value is given, display """
        """full NIC mapping. Exit after printing, ignoring other """
        """parameters.""",
        nargs='*',
        default=None)
    parser.add_argument(
        '-r', '--root-dir',
        metavar='ROOT_DIR',
        help="""The root directory of the filesystem.""",
        default='')
    parser.add_argument(
        '-p', '--provider',
        metavar='PROVIDER',
        help="""The provider to use. One of: ifcfg, eni, nmstate, iproute.""",
        choices=_PROVIDERS.keys(),
        default=None)
    parser.add_argument(
        '--purge-provider',
        metavar='PURGE_PROVIDER',
        help="""Cleans the network configurations created by the specified """
        """provider. There shall be no change in the input network """
        """config.yaml during the purge operation. One of: ifcfg, nmstate.""",
        choices=_PROVIDERS.keys(),
        default=None)
    parser.add_argument(
        '--detailed-exit-codes',
        action='store_true',
        help="""Enable detailed exit codes. If enabled an exit code of """
        """FILES_CHANGED means that files were modified. Disabled by """
        """default.""",
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

    parser.add_argument(
        '--version',
        action='version',
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
        '--minimum-config',
        action='store_true',
        help="""Apply minimum_config section before applying """
        """network_config. This is useful to apply temporary networking """
        """during migrating between providers, or to initialize networking """
        """before applying network_config. This option is not idempotent """
        """and should not be used repeatedly.""",
        dest='minimum_config',
        default=False)

    parser.add_argument(
        '--no-network-config',
        action='store_true',
        help="""Skip applying network_config section. This is useful """
        """when only --remove-config needs to be performed or when """
        """--purge-provider is used.""",
        dest='no_network_config',
        default=False)

    parser.add_argument(
        '--no-fallback-config',
        action='store_true',
        help="""Skip applying fallback_config section if errors occur """
        """while applying network_config. This is useful to leave the """
        """system in the same failed state as network_config. """,
        dest='no_fallback_config',
        default=False)

    parser.add_argument(
        '--cleanup',
        dest="cleanup",
        action='store_true',
        help="Cleanup unconfigured interfaces."
             "[DEPRECATED] For internal/developer use only "
             "(Use of --remove-config is recommended).",
        required=False)

    parser.add_argument(
        '--persist-mapping',
        dest="persist_mapping",
        action='store_true',
        help="Make aliases defined in the mapping file permanent "
             "(WARNING, permanently renames nics).",
        required=False)

    parser.add_argument(
        '--remove-config',
        dest="remove_config",
        action='store_true',
        help="""Apply remove_config section before applying network_config."""
        """ This is useful to clean previously configured interfaces. """
        """Disabled by default.""",
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
    onc_ret_code = ExitCode.SUCCESS

    opts = parse_opts(argv)

    common.set_noop(opts.noop)

    if not main_logger:
        main_logger = common.configure_logger(log_file=not opts.noop)
    common.logger_level(main_logger, opts.verbose, opts.debug)
    main_logger.info("Using config file at: %s", opts.config_file)

    config_data = {
        "remove_config": [],
        "network_config": [],
        "minimum_config": [],
        "fallback_config": [],
    }

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
    # update the nic mapping initially, so that it is consistent throughout
    mapped_nics = objects.mapped_nics(iface_mapping)
    if opts.interfaces is not None:
        reported_nics = {}
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
                    onc_ret_code |= ExitCode.ERROR
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
        return onc_ret_code

    for section in config_data.keys():
        try:
            config_data[section] = get_iface_config(
                section,
                opts.config_file,
                iface_mapping,
                persist_mapping,
                strict_validate=opts.exit_on_validation_errors,
            )
        except objects.InvalidConfigException as e:
            main_logger.error(
                "%s: Schema validation failed with error: \n%s", section, e
            )
            return get_exit_code(
                opts.detailed_exit_codes,
                onc_ret_code | ExitCode.SCHEMA_VALIDATION_FAILED
            )

    if opts.remove_config:
        if config_data["remove_config"]:
            ret_code = apply_remove_config(
                config_data["remove_config"], opts.root_dir, opts.noop
            )
            if ret_code == ExitCode.REMOVE_CONFIG_FAILED:
                main_logger.error("Failed to apply remove_config")
                return get_exit_code(
                    opts.detailed_exit_codes,
                    onc_ret_code | ExitCode.REMOVE_CONFIG_FAILED
                )
            else:
                main_logger.info("remove_config applied successfully")
        else:
            main_logger.warning(
                "--remove-config flag is set, but no 'remove_config' section "
                "found in '%s'. Please add 'remove_config' section with device"
                " entries or unset the --remove-config flag."
                "Proceeding with further section(s) of config.",
                opts.config_file
            )

    if not config_data["network_config"]:
        return get_exit_code(
            opts.detailed_exit_codes,
            onc_ret_code | ExitCode.ERROR
        )
    # Reset the DCB Config during rerun.
    # This is required to apply the new values and clear the old ones
    if utils.is_dcb_config_required():
        common.reset_dcb_map()

    if opts.purge_provider:
        if not config_data["minimum_config"] or not opts.minimum_config:
            logger.warning(
                "minimum_config is needed for safe migration. "
                "Please provide minimum_config section in the config file "
                "and use --minimum-config cli option.")

        purge_ret = unconfig_provider(
            opts.purge_provider,
            config_data["network_config"],
            opts.root_dir,
            opts.noop
        )
        onc_ret_code |= purge_ret
        if purge_ret == ExitCode.PURGE_FAILED:
            main_logger.error(
                "%s: Purge provider failed", opts.purge_provider
            )
            return get_exit_code(opts.detailed_exit_codes, onc_ret_code)
        else:
            main_logger.info(
                "%s: Purge provider completed", opts.purge_provider
            )

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
            return get_exit_code(opts.detailed_exit_codes,
                                 onc_ret_code | ExitCode.ERROR)

    if opts.minimum_config:
        if config_data["minimum_config"]:
            # Apply minimum _config using the new provider.
            ret_code = minimum_config(
                opts.provider,
                config_data["minimum_config"],
                opts.no_activate,
                opts.root_dir,
                opts.noop)
            if ret_code == ExitCode.MINIMUM_CONFIG_FAILED:
                main_logger.error("%s: Minimum config failed", opts.provider)
                return get_exit_code(opts.detailed_exit_codes, ret_code)
            else:
                main_logger.info(
                    "%s: Minimum config completed", opts.provider
                )
        else:
            onc_ret_code |= ExitCode.MINIMUM_CONFIG_FAILED
            main_logger.error(
                "--minimum-config flag provided, but no 'minimum_config' "
                "section found in '%s'. Please add a 'minimum_config' section "
                "with device entries or remove the --minimum-config flag. "
                "Proceeding with further section(s) of config.",
                opts.config_file
            )

    if not opts.no_network_config:
        if not config_data["network_config"]:
            main_logger.error("network_config is not provided")
            return get_exit_code(
                opts.detailed_exit_codes,
                onc_ret_code | ExitCode.NETWORK_CONFIG_FAILED
            )
        logger.info("%s: Applying network config", opts.provider)
        ret_code = config_provider(
            opts.provider,
            "network_config",
            config_data["network_config"],
            opts.root_dir,
            opts.noop,
            opts.no_activate,
            opts.cleanup,
        )
        if ret_code == ExitCode.ERROR:
            main_logger.error("%s: Network config failed", opts.provider)
            onc_ret_code |= ExitCode.NETWORK_CONFIG_FAILED
            if not opts.no_fallback_config and config_data["fallback_config"]:
                ret_code = safe_fallback(
                    opts.provider,
                    config_data["fallback_config"],
                    opts.no_activate,
                    opts.root_dir,
                    opts.noop
                )
                onc_ret_code |= ret_code
                return get_exit_code(opts.detailed_exit_codes, onc_ret_code)
        else:
            onc_ret_code |= ret_code
            main_logger.info("%s: Network config completed", opts.provider)
    else:
        main_logger.info("%s: skipping network_config section", opts.provider)

        # If the configuration is successful, apply the DCB config
        if has_failures(onc_ret_code) is False and \
            utils.is_dcb_config_required():
            # Apply the DCB Config
            try:
                from os_net_config import dcb_config
            except ImportError as e:
                logger.error("DCB configuration failed: %s", e)
                return get_exit_code(
                    opts.detailed_exit_codes,
                    onc_ret_code | ExitCode.DCB_CONFIG_FAILED
                )
            utils.configure_dcb_config_service()
            dcb_apply = dcb_config.DcbApplyConfig()
            dcb_apply.apply()
            main_logger.info("%s: DCB config completed", opts.provider)
    return get_exit_code(opts.detailed_exit_codes, onc_ret_code)


def apply_remove_config(remove_config, root_dir, noop):
    """Remove given network devices using the appropriate backend method.

    - Classify each requested device by provider (ifcfg or nmstate)
    - Invoke the corr provider removal method. Aggregates success/failure.
    - Handle excpetion of provider initialisation

    :param remove_config: List of remove entries (dicts)
    :param root_dir: Filesystem root prefix for provider operations
    :param noop: If True, perform a dry run without applying changes
    :returns: ExitCode, which is updated based on remove_devices() status
    """

    nmstate_remove_config = []
    ifcfg_remove_config = []

    try:
        rm_ifcfg_provider = load_provider("ifcfg", noop, root_dir)
    except ImportError as e:
        logger.error("ifcfg: cannot load provider, error %s", e)
        rm_ifcfg_provider = None

    try:
        rm_nmstate_provider = load_provider("nmstate", noop, root_dir)
    except ImportError as e:
        logger.error("nmstate: cannot load provider, error %s", e)
        rm_nmstate_provider = None

    for rem_json in remove_config:
        rem_json.update({"type": "remove_net_device"})
        removeobj = objects.object_from_json(rem_json)
        # Skip loopback interface
        if removeobj.remove_name == 'lo':
            logger.info("Skipping loopback interface \'lo\'")
            continue

        logger.info(
            "%s: type=%s provider=?",
            removeobj.remove_name,
            removeobj.remove_type
        )
        if rm_ifcfg_provider and \
            rm_ifcfg_provider.is_device_managed(removeobj):
            logger.info(
                "%s: type=%s provider=ifcfg",
                removeobj.remove_name,
                removeobj.remove_type
            )
            ifcfg_remove_config.append(removeobj)
        elif rm_nmstate_provider and \
            rm_nmstate_provider.is_device_managed(removeobj):
            logger.info(
                "%s: type=%s provider=nmstate",
                removeobj.remove_name,
                removeobj.remove_type
            )
            nmstate_remove_config.append(removeobj)
        else:
            logger.info(
                "%s: type=%s device not found",
                removeobj.remove_name,
                removeobj.remove_type
            )

    success = True
    if ifcfg_remove_config:
        ret_code = rm_ifcfg_provider.remove_devices(ifcfg_remove_config)
        if ret_code != ExitCode.SUCCESS:
            logger.error("ifcfg: Failed to remove interfaces")
            success = False
        else:
            logger.info(
                "%s: removed %s interfaces using ifcfg", "ifcfg",
                len(ifcfg_remove_config)
            )

    if nmstate_remove_config:
        ret_code = rm_nmstate_provider.remove_devices(nmstate_remove_config)
        if ret_code != ExitCode.SUCCESS:
            logger.error("nmstate: Failed to remove interfaces")
            success = False
        else:
            logger.info(
                "%s: removed %s interfaces using nmstate", "nmstate",
                len(nmstate_remove_config)
            )
    return ExitCode.SUCCESS if success else ExitCode.REMOVE_CONFIG_FAILED


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
        return ExitCode.PURGE_FAILED

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
    if cleanup:
        logger.warning(
            "!!! Deprecated cleanup flag set. "
            "Use of --remove-config is recommended.)"
        )
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
            "%s: %s configuration completed", provider_name, config_name
        )

    except Exception as e:
        logger.error(
            "%s: ***Failed to configure %s ***\n%s\n%s",
            provider_name,
            config_name,
            e,
            traceback.format_exc()
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
        except IOError:
            logger.error("Error reading file: %s", config_file)
            return []
        except (yaml.scanner.ScannerError, yaml.parser.ParserError) as e:
            logger.error("Invalid YAML in config file %s: %s", config_file, e)
            return []
    else:
        logger.error("The config file %s is not found", config_file)
        return []

    if not isinstance(iface_array, list):
        logger.info(
            "interfaces are not defined in %s section of %s",
            config_name,
            config_file
        )
        return []

    common.print_config(iface_array, config_name)
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

    for iface_json in iface_array:
        if iface_json.get('type') != 'route_table':
            iface_json.update({'nic_mapping': iface_map})
            iface_json.update({'persist_mapping': persist_map})

    return iface_array


def safe_fallback(provider,
                  fb_config,
                  no_activate,
                  root_dir,
                  noop):
    if not fb_config:
        logger.error("fallback_config is not provided")
        return ExitCode.FALLBACK_FAILED

    if len(fb_config) > 2:
        logger.error(
            "fallback_config shall be strictly used for SSH restoration"
        )
        return ExitCode.FALLBACK_FAILED

    logger.info("%s: Running safe fallback", provider)
    ret = config_provider(
        provider,
        "fallback_config",
        fb_config,
        root_dir,
        noop,
        no_activate,
        False,
    )
    if ret == ExitCode.ERROR:
        logger.error("%s: failed to configure fallback_config", provider)
        return ExitCode.FALLBACK_FAILED
    else:
        logger.info("%s: fallback_config is completed", provider)
        return ExitCode.SUCCESS


def minimum_config(provider,
                   min_config,
                   no_activate,
                   root_dir,
                   noop):
    if not min_config:
        logger.error(
            "minimum_config is not provided in config file"
        )
        return ExitCode.MINIMUM_CONFIG_FAILED

    logger.info("%s: Running minimum config", provider)
    ret = config_provider(
        provider,
        "minimum_config",
        min_config,
        root_dir,
        noop,
        no_activate,
        False,
    )
    if ret == ExitCode.ERROR:
        logger.error("%s: minimum_config failed", provider)
        return ExitCode.MINIMUM_CONFIG_FAILED
    else:
        logger.info("%s: minimum_config completed", provider)
        return ExitCode.SUCCESS


if __name__ == '__main__':
    sys.exit(main(sys.argv, main_logger=logger))
