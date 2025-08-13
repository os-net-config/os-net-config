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

from io import StringIO
import os.path
import random
import re
import sys
import yaml

import os_net_config
from os_net_config import cli
from os_net_config.cli import ExitCode
from os_net_config import common
from os_net_config.tests import base


REALPATH = os.path.dirname(os.path.realpath(__file__))
SAMPLE_BASE = os.path.join(REALPATH, '../../', 'etc',
                           'os-net-config', 'samples')


def generate_random_mac(name):
    # Generate 6 random bytes
    mac = [random.randint(0, 255) for _ in range(6)]
    mac[0] &= 0xFE
    mac_address = ':'.join(f'{byte:02x}' for byte in mac)
    return mac_address


class TestCli(base.TestCase):

    def setUp(self):
        super(TestCli, self).setUp()
        rand = str(int(random.random() * 100000))
        common.SRIOV_CONFIG_FILE = '/tmp/sriov_config_' + rand + '.yaml'
        common._LOG_FILE = '/tmp/' + rand + 'os_net_config.log'
        common.set_noop(False)
        sys.stdout = StringIO()
        sys.stderr = StringIO()
        self.stub_out('os_net_config.common.interface_mac',
                      generate_random_mac)

        def stub_is_ovs_installed():
            return True
        self.stub_out('os_net_config.utils.is_ovs_installed',
                      stub_is_ovs_installed)

        def test_update_sriov_pf_map(ifname, numvfs, noop, promisc=None,
                                     link_mode='legacy', vdpa=False,
                                     steering_mode=None,
                                     lag_candidate=None,
                                     drivers_autoprobe=True,
                                     pci_address=None, mac_address=None):
            return
        self.stub_out('os_net_config.utils.update_sriov_pf_map',
                      test_update_sriov_pf_map)

    def tearDown(self):
        super(TestCli, self).tearDown()
        if os.path.isfile(common._LOG_FILE):
            os.remove(common._LOG_FILE)
        if os.path.isfile(common.SRIOV_CONFIG_FILE):
            os.remove(common.SRIOV_CONFIG_FILE)

    def run_cli(self, argstr, exitcodes=(ExitCode.SUCCESS,)):
        for s in [sys.stdout, sys.stderr]:
            s.flush()
            s.truncate(0)
            s.seek(0)
        ret = cli.main(argstr.split())
        self.assertIn(ret, exitcodes)
        sys.stdout.flush()
        sys.stderr.flush()
        stdout = sys.stdout.getvalue()
        stderr = sys.stderr.getvalue()
        return (stdout, stderr)

    def stub_get_pci_address(self, ifname):
        address_map = {
            "eth0": "0000:00:07.0",
            "eth1": "0000:00:08.0",
            "eth2": "0000:00:09.0",
            "em3": "0000:00:03.0",
            "em1": "0000:00:01.0"
        }
        return address_map.get(ifname, None)

    def test_bond_noop_output(self):
        timestamp_rex = re.compile(
            (r'bond\.(yaml|json)|^[\d]{4}-[\d]{2}-[\d]{2} '
             r'[\d]{2}:[\d]{2}:[\d]{2}\.[\d]{3} '),
            flags=re.M
        )
        bond_yaml = os.path.join(SAMPLE_BASE, 'bond.yaml')
        bond_json = os.path.join(SAMPLE_BASE, 'bond.json')
        stdout_yaml, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s' % bond_yaml)
        self.assertEqual('', stderr)
        stdout_json, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s' % bond_json)
        self.assertEqual('', stderr)
        sanity_devices = ['DEVICE=br-ctlplane',
                          'DEVICE=em2',
                          'DEVICE=em1',
                          'DEVICE=bond1',
                          'DEVICETYPE=ovs']
        for dev in sanity_devices:
            self.assertIn(dev, stdout_yaml)
        stdout_yaml = timestamp_rex.sub('', stdout_yaml)
        stdout_json = timestamp_rex.sub('', stdout_json)
        self.assertEqual(stdout_yaml, stdout_json)

    def test_ivs_noop_output(self):
        timestamp_rex = re.compile(
            (r'ivs\.(yaml|json)|^[\d]{4}-[\d]{2}-[\d]{2} '
             r'[\d]{2}:[\d]{2}:[\d]{2}\.[\d]{3} '),
            flags=re.M
        )
        ivs_yaml = os.path.join(SAMPLE_BASE, 'ivs.yaml')
        ivs_json = os.path.join(SAMPLE_BASE, 'ivs.json')
        stdout_yaml, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s' % ivs_yaml)
        self.assertEqual('', stderr)
        stdout_json, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s' % ivs_json)
        self.assertEqual('', stderr)
        sanity_devices = ['DEVICE=nic2',
                          'DEVICE=nic3',
                          'DEVICE=api201',
                          'DEVICE=storage202',
                          'DEVICETYPE=ivs']
        for dev in sanity_devices:
            self.assertIn(dev, stdout_yaml)
        stdout_yaml = timestamp_rex.sub('', stdout_yaml)
        stdout_json = timestamp_rex.sub('', stdout_json)
        self.assertEqual(stdout_yaml, stdout_json)

    def test_bridge_noop_output(self):
        timestamp_rex = re.compile(
            (r'bridge_dhcp\.(yaml|json)|^[\d]{4}-[\d]{2}-[\d]{2} '
             r'[\d]{2}:[\d]{2}:[\d]{2}\.[\d]{3} '),
            flags=re.M
        )
        bridge_yaml = os.path.join(SAMPLE_BASE, 'bridge_dhcp.yaml')
        bridge_json = os.path.join(SAMPLE_BASE, 'bridge_dhcp.json')
        stdout_yaml, stderr = self.run_cli('ARG0 --provider=eni --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s' % bridge_yaml)
        self.assertEqual('', stderr)
        stdout_json, stderr = self.run_cli('ARG0 --provider=eni --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s' % bridge_json)
        self.assertEqual('', stderr)
        sanity_devices = ['iface br-ctlplane inet dhcp',
                          'iface em1',
                          'ovs_type OVSBridge']
        for dev in sanity_devices:
            self.assertIn(dev, stdout_yaml)
        stdout_yaml = timestamp_rex.sub('', stdout_yaml)
        stdout_json = timestamp_rex.sub('', stdout_json)
        self.assertEqual(stdout_yaml, stdout_json)

    def test_vlan_noop_output(self):
        timestamp_rex = re.compile(
            (r'bridge_vlan\.(yaml|json)|^[\d]{4}-[\d]{2}-[\d]{2} '
             r'[\d]{2}:[\d]{2}:[\d]{2}\.[\d]{3} '),
            flags=re.M
        )
        vlan_yaml = os.path.join(SAMPLE_BASE, 'bridge_vlan.yaml')
        vlan_json = os.path.join(SAMPLE_BASE, 'bridge_vlan.json')
        stdout_yaml, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s' % vlan_yaml)
        self.assertEqual('', stderr)
        stdout_json, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s' % vlan_json)
        self.assertEqual('', stderr)
        sanity_devices = ['DEVICE=br-ctlplane',
                          'DEVICE=em1',
                          'DEVICE=vlan16',
                          'DEVICETYPE=ovs']
        for dev in sanity_devices:
            self.assertIn(dev, stdout_yaml)
        stdout_yaml = timestamp_rex.sub('', stdout_yaml)
        stdout_json = timestamp_rex.sub('', stdout_json)
        self.assertEqual(stdout_yaml, stdout_json)

    def test_interface_noop_output(self):
        timestamp_rex = re.compile(
            (r'interface\.(yaml|json)|^[\d]{4}-[\d]{2}-[\d]{2} '
             r'[\d]{2}:[\d]{2}:[\d]{2}\.[\d]{3} '),
            flags=re.M
        )
        interface_yaml = os.path.join(SAMPLE_BASE, 'interface.yaml')
        interface_json = os.path.join(SAMPLE_BASE, 'interface.json')
        stdout_yaml, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s' % interface_yaml)
        self.assertEqual('', stderr)
        stdout_json, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s' % interface_json)
        self.assertEqual('', stderr)
        sanity_devices = ['DEVICE=em1',
                          'BOOTPROTO=static',
                          'IPADDR=192.0.2.1']
        for dev in sanity_devices:
            self.assertIn(dev, stdout_yaml)
        stdout_yaml = timestamp_rex.sub('', stdout_yaml)
        stdout_json = timestamp_rex.sub('', stdout_json)
        self.assertEqual(stdout_yaml, stdout_json)

    def test_bridge_noop_rootfs(self):
        for provider in ('ifcfg', 'eni'):
            bond_yaml = os.path.join(SAMPLE_BASE, 'bridge_dhcp.yaml')
            stdout_yaml, stderr = self.run_cli('ARG0 --provider=%s --noop '
                                               '--exit-on-validation-errors '
                                               '--root-dir=/rootfs '
                                               '-c %s' % (provider, bond_yaml))
            self.assertEqual('', stderr)
            self.assertIn('File: /rootfs/', stdout_yaml)

    def test_interface_noop_detailed_exit_codes(self):
        interface_yaml = os.path.join(SAMPLE_BASE, 'interface.yaml')
        stdout_yaml, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s --detailed-exit-codes'
                                           % interface_yaml,
                                           exitcodes=(ExitCode.FILES_CHANGED,))

    def test_interface_noop_detailed_exit_codes_no_changes(self):
        interface_yaml = os.path.join(SAMPLE_BASE, 'interface.yaml')

        class TestImpl(os_net_config.NetConfig):

            def add_interface(self, interface):
                pass

            def apply(self, cleanup=False, activate=True):
                # this fake implementation returns no changes
                return {}

        self.stub_out('os_net_config.impl_ifcfg.IfcfgNetConfig', TestImpl)
        stdout_yaml, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s --detailed-exit-codes'
                                           % interface_yaml,
                                           exitcodes=(ExitCode.SUCCESS,))

    def test_sriov_noop_output(self):
        def test_get_vf_devname(device, vfid):
            return device + '_' + str(vfid)

        def test_get_pci_address(ifname):
            return '0000:79:10.2'

        def test_interface_mac(name):
            return 'AA:BB:CC:DD:EE:FF'

        def test_get_default_vf_driver(device, vfid):
            return 'iavf'

        def test_get_pci_device_driver(pci_address):
            return 'iavf'

        timestamp_rex = re.compile(
            (r'sriov_pf\.(yaml|json)|^[\d]{4}-[\d]{2}-[\d]{2} '
             r'[\d]{2}:[\d]{2}:[\d]{2}\.[\d]{3} '),
            flags=re.M
        )
        self.stub_out('os_net_config.utils.get_vf_devname',
                      test_get_vf_devname)
        self.stub_out('os_net_config.common.get_pci_address',
                      test_get_pci_address)
        self.stub_out('os_net_config.common.interface_mac',
                      test_interface_mac)
        self.stub_out('os_net_config.common.get_default_vf_driver',
                      test_get_default_vf_driver)
        self.stub_out('os_net_config.common.get_pci_device_driver',
                      test_get_pci_device_driver)
        ivs_yaml = os.path.join(SAMPLE_BASE, 'sriov_pf.yaml')
        ivs_json = os.path.join(SAMPLE_BASE, 'sriov_pf.json')
        stdout_yaml, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s' % ivs_yaml)
        self.assertEqual('', stderr)
        stdout_json, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s' % ivs_json)
        self.assertEqual('', stderr)
        sanity_devices = ['DEVICE=p2p1',
                          'DEVICE=p2p1_5',
                          'DEVICE=p2p1_1',
                          'DEVICE=br-vfs',
                          'DEVICE=br-bond',
                          'TYPE=OVSBridge']
        for dev in sanity_devices:
            self.assertIn(dev, stdout_yaml)
        stdout_yaml = timestamp_rex.sub('', stdout_yaml)
        stdout_json = timestamp_rex.sub('', stdout_json)
        self.assertEqual(stdout_yaml, stdout_json)

    def test_sriov_vf_with_dpdk_noop_output(self):
        def test_get_vf_devname(device, vfid):
            return device + '_' + str(vfid)

        def test_get_pci_address(ifname):
            return '0000:79:10.2'

        def test_get_default_vf_driver(device, vfid):
            return 'iavf'

        def test_get_pci_device_driver(pci_address):
            return 'iavf'

        timestamp_rex = re.compile(
            (r'sriov_pf_ovs_dpdk\.(yaml|json)|^[\d]{4}-[\d]{2}-[\d]{2} '
             r'[\d]{2}:[\d]{2}:[\d]{2}\.[\d]{3} '),
            flags=re.M
        )
        self.stub_out('os_net_config.utils.get_vf_devname',
                      test_get_vf_devname)
        self.stub_out('os_net_config.common.get_pci_address',
                      test_get_pci_address)
        self.stub_out('os_net_config.common.get_default_vf_driver',
                      test_get_default_vf_driver)
        self.stub_out('os_net_config.common.get_pci_device_driver',
                      test_get_pci_device_driver)
        pf_yaml = os.path.join(SAMPLE_BASE, 'sriov_pf_ovs_dpdk.yaml')
        pf_json = os.path.join(SAMPLE_BASE, 'sriov_pf_ovs_dpdk.json')
        stdout_yaml, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s' % pf_yaml)
        self.assertEqual('', stderr)
        stdout_json, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s' % pf_json)
        self.assertEqual('', stderr)
        sanity_devices = ['DEVICE=p2p1',
                          'DEVICE=p2p1_5',
                          'DEVICE=br-vfs',
                          'TYPE=OVSUserBridge',
                          'DEVICE=dpdk0',
                          'TYPE=OVSDPDKPort']
        for dev in sanity_devices:
            self.assertIn(dev, stdout_yaml)
        stdout_yaml = timestamp_rex.sub('', stdout_yaml)
        stdout_json = timestamp_rex.sub('', stdout_json)
        self.assertEqual(stdout_yaml, stdout_json)

    def test_ovs_dpdk_bond_noop_output(self):
        timestamp_rex = re.compile(
            (r'ovs_dpdk_bond\.(yaml|json)|^[\d]{4}-[\d]{2}-[\d]{2} '
             r'[\d]{2}:[\d]{2}:[\d]{2}\.[\d]{3} '),
            flags=re.M
        )
        ivs_yaml = os.path.join(SAMPLE_BASE, 'ovs_dpdk_bond.yaml')
        ivs_json = os.path.join(SAMPLE_BASE, 'ovs_dpdk_bond.json')
        stdout_yaml, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s' % ivs_yaml)
        self.assertEqual('', stderr)
        stdout_json, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s' % ivs_json)
        self.assertEqual('', stderr)
        sanity_devices = ['DEVICE=br-link',
                          'TYPE=OVSUserBridge',
                          'DEVICE=dpdkbond0',
                          'TYPE=OVSDPDKBond']
        for dev in sanity_devices:
            self.assertIn(dev, stdout_yaml)
        stdout_yaml = timestamp_rex.sub('', stdout_yaml)
        stdout_json = timestamp_rex.sub('', stdout_json)
        self.assertEqual(stdout_yaml, stdout_json)

    def test_nfvswitch_noop_output(self):
        timestamp_rex = re.compile(
            (r'nfvswitch\.(yaml|json)|^[\d]{4}-[\d]{2}-[\d]{2} '
             r'[\d]{2}:[\d]{2}:[\d]{2}\.[\d]{3} '),
            flags=re.M
        )
        nfvswitch_yaml = os.path.join(SAMPLE_BASE, 'nfvswitch.yaml')
        nfvswitch_json = os.path.join(SAMPLE_BASE, 'nfvswitch.json')
        stdout_yaml, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s' % nfvswitch_yaml)
        self.assertEqual('', stderr)
        stdout_json, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s' % nfvswitch_json)
        self.assertEqual('', stderr)
        sanity_devices = ['DEVICE=nic2',
                          'DEVICE=nic3',
                          'DEVICE=api201',
                          'DEVICE=storage202',
                          'DEVICETYPE=nfvswitch']
        for dev in sanity_devices:
            self.assertIn(dev, stdout_yaml)
        stdout_yaml = timestamp_rex.sub('', stdout_yaml)
        stdout_json = timestamp_rex.sub('', stdout_json)
        self.assertEqual(stdout_yaml, stdout_json)

    def test_ovs_dpdk_noop_output(self):
        timestamp_rex = re.compile(
            (r'ovs_dpdk\.(yaml|json)|^[\d]{4}-[\d]{2}-[\d]{2} '
             r'[\d]{2}:[\d]{2}:[\d]{2}\.[\d]{3} '),
            flags=re.M
        )
        ivs_yaml = os.path.join(SAMPLE_BASE, 'ovs_dpdk.yaml')
        ivs_json = os.path.join(SAMPLE_BASE, 'ovs_dpdk.json')
        stdout_yaml, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s' % ivs_yaml)
        self.assertEqual('', stderr)
        stdout_json, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s' % ivs_json)
        self.assertEqual('', stderr)
        sanity_devices = ['DEVICE=br-link',
                          'TYPE=OVSUserBridge',
                          'DEVICE=dpdk0',
                          'TYPE=OVSDPDKPort']
        for dev in sanity_devices:
            self.assertIn(dev, stdout_yaml)
        stdout_yaml = timestamp_rex.sub('', stdout_yaml)
        stdout_json = timestamp_rex.sub('', stdout_json)
        self.assertEqual(stdout_yaml, stdout_json)

    def test_nic_mapping_report_output(self):
        mapping_report = os.path.join(SAMPLE_BASE, 'mapping_report.yaml')

        def dummy_mapped_nics(nic_mapping=None):
            return nic_mapping
        self.stub_out('os_net_config.objects.mapped_nics', dummy_mapped_nics)

        stdout, stderr = self.run_cli('ARG0 --interfaces '
                                      '--exit-on-validation-errors '
                                      '-m %s' % mapping_report)
        self.assertEqual('', stderr)
        stdout_list = yaml.safe_load(stdout)
        self.assertEqual(stdout_list['nic1'], 'em1')
        self.assertEqual(stdout_list['nic2'], 'em2')
        self.assertEqual(stdout_list['nic3'], 'em4')
        self.assertEqual(stdout_list['nic4'], 'em3')

    def test_nic_mapping_report_with_explicit_interface_name(self):
        mapping_report = os.path.join(SAMPLE_BASE, 'mapping_report.yaml')

        def dummy_mapped_nics(nic_mapping=None):
            return nic_mapping
        self.stub_out('os_net_config.objects.mapped_nics', dummy_mapped_nics)

        stdout, stderr = self.run_cli('ARG0 --interfaces em2 em3 '
                                      '--exit-on-validation-errors '
                                      '-m %s' % mapping_report)
        self.assertEqual('', stderr)
        stdout_list = yaml.safe_load(stdout)
        self.assertNotIn('em1', stdout_list.keys())
        self.assertNotIn('em1', stdout_list.values())
        self.assertEqual(stdout_list['em2'], 'em2')
        self.assertEqual(stdout_list['em3'], 'em3')
        self.assertNotIn('em4', stdout_list.keys())
        self.assertNotIn('em4', stdout_list.values())

    def test_contrail_vrouter_noop_output(self):
        timestamp_rex = re.compile(
            (r'contrail_vrouter\.(yaml|json)|^[\d]{4}-[\d]{2}-[\d]{2} '
             r'[\d]{2}:[\d]{2}:[\d]{2}\.[\d]{3} '),
            flags=re.M
        )
        cvi_yaml = os.path.join(SAMPLE_BASE, 'contrail_vrouter.yaml')
        cvi_json = os.path.join(SAMPLE_BASE, 'contrail_vrouter.json')
        stdout_yaml, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s' % cvi_yaml)
        self.assertEqual('', stderr)
        stdout_json, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s' % cvi_json)
        self.assertEqual('', stderr)
        sanity_devices = ['DEVICE=vhost0',
                          'BIND_INT=em3',
                          'DEVICETYPE=vhost',
                          'TYPE=kernel_mode']
        for dev in sanity_devices:
            self.assertIn(dev, stdout_yaml)
        stdout_yaml = timestamp_rex.sub('', stdout_yaml)
        stdout_json = timestamp_rex.sub('', stdout_json)
        self.assertEqual(stdout_yaml, stdout_json)

    def test_contrail_vrouter_vlan_noop_output(self):
        timestamp_rex = re.compile(
            (r'contrail_vrouter_vlan\.(yaml|json)|^[\d]{4}-[\d]{2}-[\d]{2} '
             r'[\d]{2}:[\d]{2}:[\d]{2}\.[\d]{3} '),
            flags=re.M
        )
        cvi_yaml = os.path.join(SAMPLE_BASE, 'contrail_vrouter_vlan.yaml')
        cvi_json = os.path.join(SAMPLE_BASE, 'contrail_vrouter_vlan.json')
        stdout_yaml, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s' % cvi_yaml)
        self.assertEqual('', stderr)
        stdout_json, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s' % cvi_json)
        self.assertEqual('', stderr)
        sanity_devices = ['DEVICE=vhost0',
                          'BIND_INT=vlan100',
                          'DEVICETYPE=vhost',
                          'TYPE=kernel_mode']
        for dev in sanity_devices:
            self.assertIn(dev, stdout_yaml)
        stdout_yaml = timestamp_rex.sub('', stdout_yaml)
        stdout_json = timestamp_rex.sub('', stdout_json)
        self.assertEqual(stdout_yaml, stdout_json)

    def test_contrail_vrouter_dpdk_noop_output(self):
        common.set_noop(False)
        timestamp_rex = re.compile(
            (r'contrail_vrouter_dpdk\.(yaml|json)|^[\d]{4}-[\d]{2}-[\d]{2} '
             r'[\d]{2}:[\d]{2}:[\d]{2}\.[\d]{3} '),
            flags=re.M
        )
        cvi_yaml = os.path.join(SAMPLE_BASE, 'contrail_vrouter_dpdk.yaml')
        cvi_json = os.path.join(SAMPLE_BASE, 'contrail_vrouter_dpdk.json')
        self.stub_out('os_net_config.common.get_pci_address',
                      self.stub_get_pci_address)
        stdout_yaml, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '--debug '
                                           '-c %s' % cvi_yaml)
        self.assertEqual('', stderr)
        stdout_json, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '--debug '
                                           '-c %s' % cvi_json)
        self.assertEqual('', stderr)
        sanity_devices = ['DEVICE=vhost0',
                          'BIND_INT=0000:00:03.0',
                          'DEVICETYPE=vhost',
                          'TYPE=dpdk']
        for dev in sanity_devices:
            self.assertIn(dev, stdout_yaml)
        stdout_yaml = timestamp_rex.sub('', stdout_yaml)
        stdout_json = timestamp_rex.sub('', stdout_json)
        self.assertEqual(stdout_yaml, stdout_json)

    def test_config_provider_success(self):
        """Test config_provider function with successful configuration"""

        class MockProvider(os_net_config.NetConfig):
            def __init__(self, noop=False, root_dir=''):
                super(MockProvider, self).__init__(noop, root_dir)
                self.added_objects = []

            def add_object(self, obj):
                self.added_objects.append(obj)

            def apply(self, cleanup=False, activate=True,
                      config_rules_dns=True):
                return {'/tmp/test_config': 'test content'}

        def mock_load_provider(provider_name, noop, root_dir):
            return MockProvider(noop, root_dir)

        self.stub_out('os_net_config.cli.load_provider', mock_load_provider)

        # Test successful configuration
        iface_config = [{"type": "interface", "name": "eth0"}]
        ret_code = cli.config_provider(
            "iifcfg", "network_config", iface_config,
            "", False, False, False
        )

        self.assertEqual(ExitCode.FILES_CHANGED, ret_code)

    def test_config_provider_failure(self):
        """Test config_provider function with provider loading failure"""

        def mock_load_provider_fail(provider_name, noop, root_dir):
            raise ImportError("Failed to load provider")

        self.stub_out(
            'os_net_config.cli.load_provider', mock_load_provider_fail
        )

        # Test provider loading failure
        iface_config = [{"type": "interface", "name": "eth0"}]
        ret_code = cli.config_provider(
            "ifcfg", "network_config", iface_config,
            "", False, False, False
        )

        self.assertEqual(ExitCode.ERROR, ret_code)

    def test_unconfig_provider_success(self):
        """Test unconfig_provider function with successful cleanup"""

        class MockProvider(os_net_config.NetConfig):
            def __init__(self, noop=False, root_dir=''):
                super(MockProvider, self).__init__(noop, root_dir)
                self.deleted_objects = []

            def del_object(self, obj):
                self.deleted_objects.append(obj)

            def destroy(self):
                pass

        def mock_load_provider(provider_name, noop, root_dir):
            return MockProvider(noop, root_dir)

        self.stub_out('os_net_config.cli.load_provider', mock_load_provider)

        # Test successful cleanup
        iface_array = [{"type": "interface", "name": "eth0"}]
        ret_code = cli.unconfig_provider("ifcfg", iface_array, "", False)

        self.assertEqual(ExitCode.SUCCESS, ret_code)

    def test_unconfig_provider_failure(self):
        """Test unconfig_provider function with provider loading failure"""

        def mock_load_provider_fail(provider_name, noop, root_dir):
            raise ImportError("Failed to load purge provider")

        self.stub_out(
            'os_net_config.cli.load_provider', mock_load_provider_fail
        )

        # Test provider loading failure
        iface_array = [{"type": "interface", "name": "eth0"}]
        ret_code = cli.unconfig_provider("ifcfg", iface_array, "", False)

        self.assertEqual(ExitCode.PURGE_FAILED, ret_code)

    def test_get_iface_config_success(self):
        """Test successful config reading and validation"""
        config_data = {
            'network_config': [
                {'type': 'interface', 'name': 'eth0'},
                {'type': 'interface', 'name': 'eth1'}
            ]
        }
        config_file = '/tmp/test_config.yaml'

        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)

        try:
            result = cli.get_iface_config(
                'network_config', config_file, {}, False
            )
            self.assertEqual(len(result), 2)
            self.assertEqual(result[0]['name'], 'eth0')
            self.assertEqual(result[1]['name'], 'eth1')
            # Check NIC mapping was added
            self.assertIn('nic_mapping', result[0])
            self.assertIn('persist_mapping', result[0])
        finally:
            if os.path.exists(config_file):
                os.remove(config_file)

    def test_get_iface_config_file_not_exists(self):
        """Test handling of non-existent config file"""
        result = cli.get_iface_config(
            'network_config', '/nonexistent/file.yaml', {}, False
        )
        self.assertEqual(result, [])

    def test_get_iface_config_io_error(self):
        """Test handling of IO errors when reading config file"""
        # Create a directory instead of file to trigger IOError
        config_path = '/tmp/test_config_dir'
        os.makedirs(config_path, exist_ok=True)

        try:
            result = cli.get_iface_config(
                'network_config', config_path, {}, False
            )
            self.assertEqual(result, [])
        finally:
            if os.path.exists(config_path):
                os.rmdir(config_path)

    def test_get_iface_config_invalid_yaml(self):
        """Test handling of invalid YAML content"""
        config_file = '/tmp/test_invalid.yaml'

        with open(config_file, 'w') as f:
            f.write('invalid: yaml: content: [')

        try:
            result = cli.get_iface_config(
                'network_config', config_file, {}, False
            )
            self.assertEqual(result, [])
        finally:
            if os.path.exists(config_file):
                os.remove(config_file)

    def test_get_iface_config_missing_section(self):
        """Test handling when config section is missing"""
        config_data = {'other_section': []}
        config_file = '/tmp/test_missing_section.yaml'

        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)

        try:
            result = cli.get_iface_config(
                'network_config', config_file, {}, False
            )
            self.assertEqual(result, [])
        finally:
            if os.path.exists(config_file):
                os.remove(config_file)

    def test_get_iface_config_not_list(self):
        """Test handling when config section is not a list"""
        config_data = {
            'network_config': {'invalid': 'not a list'}
        }
        config_file = '/tmp/test_not_list.yaml'

        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)

        try:
            result = cli.get_iface_config(
                'network_config', config_file, {}, False
            )
            self.assertEqual(result, [])
        finally:
            if os.path.exists(config_file):
                os.remove(config_file)

    def test_get_iface_config_route_table_excluded(self):
        """Test that route_table entries are excluded from NIC mapping"""
        config_data = {
            'network_config': [
                {'type': 'interface', 'name': 'eth0'},
                {'type': 'route_table', 'table_id': 200, 'name': 'custom'}
            ]
        }
        config_file = '/tmp/test_route_table.yaml'
        iface_mapping = {'nic1': 'eth0'}

        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)

        try:
            result = cli.get_iface_config(
                'network_config', config_file, iface_mapping, True
            )
            self.assertEqual(len(result), 2)
            # Interface should have mapping
            self.assertEqual(result[0]['nic_mapping'], iface_mapping)
            self.assertEqual(result[0]['persist_mapping'], True)
            # Route table should not have mapping
            self.assertNotIn('nic_mapping', result[1])
            self.assertNotIn('persist_mapping', result[1])
        finally:
            if os.path.exists(config_file):
                os.remove(config_file)

    def test_get_iface_config_strict_validation_success(self):
        """Test strict validation mode with valid config"""
        config_data = {
            'network_config': [
                {'type': 'interface', 'name': 'eth0'}
            ]
        }
        config_file = '/tmp/test_strict_valid.yaml'

        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)

        try:
            # Mock validator to return no errors
            def mock_validate_config(config):
                return []
            self.stub_out('os_net_config.validator.validate_config',
                          mock_validate_config)

            result = cli.get_iface_config(
                'network_config', config_file, {}, False, strict_validate=True
            )
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]['name'], 'eth0')
        finally:
            if os.path.exists(config_file):
                os.remove(config_file)

    def test_get_iface_config_strict_validation_failure(self):
        """Test strict validation mode with invalid config raises exception"""
        config_data = {
            'network_config': [
                {'type': 'interface', 'invalid_field': 'value'}
            ]
        }
        config_file = '/tmp/test_strict_invalid.yaml'

        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)

        # Mock validator to return errors
        def mock_validate_config(config):
            return ['Validation error 1', 'Validation error 2']
        self.stub_out('os_net_config.validator.validate_config',
                      mock_validate_config)
        self.assertRaises(
            os_net_config.objects.InvalidConfigException,
            cli.get_iface_config,
            'network_config',
            config_file,
            {},
            False,
            strict_validate=True
        )
        if os.path.exists(config_file):
            os.remove(config_file)

    def test_get_iface_config_warning_validation(self):
        """Test warning-only validation mode logs warnings but continues"""
        config_data = {
            'network_config': [
                {'type': 'interface', 'name': 'eth0'}
            ]
        }
        config_file = '/tmp/test_warning_validation.yaml'

        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)

        try:
            # Mock validator to return errors
            def mock_validate_config(config):
                return ['Warning: Invalid configuration']
            self.stub_out('os_net_config.validator.validate_config',
                          mock_validate_config)

            result = cli.get_iface_config(
                'network_config', config_file, {}, False, strict_validate=False
            )
            # Should still return config despite validation warnings
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]['name'], 'eth0')
        finally:
            if os.path.exists(config_file):
                os.remove(config_file)

    def test_get_iface_config_with_nic_mapping(self):
        """Test config with NIC mapping applied correctly"""
        config_data = {
            'network_config': [
                {'type': 'interface', 'name': 'nic1'},
                {'type': 'interface', 'name': 'nic2'}
            ]
        }
        config_file = '/tmp/test_nic_mapping.yaml'
        iface_mapping = {'nic1': 'eth0', 'nic2': 'eth1'}

        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)

        try:
            result = cli.get_iface_config(
                'network_config', config_file, iface_mapping, True
            )
            self.assertEqual(len(result), 2)
            for iface in result:
                self.assertEqual(iface['nic_mapping'], iface_mapping)
                self.assertEqual(iface['persist_mapping'], True)
        finally:
            if os.path.exists(config_file):
                os.remove(config_file)

    def test_get_iface_config_empty_config(self):
        """Test handling of empty config list"""
        config_data = {
            'network_config': []
        }
        config_file = '/tmp/test_empty_config.yaml'

        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)

        try:
            result = cli.get_iface_config(
                'network_config', config_file, {}, False
            )
            self.assertEqual(result, [])
        finally:
            if os.path.exists(config_file):
                os.remove(config_file)
