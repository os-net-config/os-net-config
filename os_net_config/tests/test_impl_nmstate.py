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

from libnmstate.schema import Ethernet
from libnmstate.schema import Ethtool

from libnmstate.schema import InterfaceType
from libnmstate.schema import OVSBridge
import os.path
import random
import tempfile
import yaml

import os_net_config
from os_net_config import common
from os_net_config import impl_nmstate
from os_net_config import objects
from os_net_config.tests import base
from os_net_config import utils


TEST_ENV_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__),
                                             'environment'))

_RT_DEFAULT = """# reserved values
#
255\tlocal
254\tmain
253\tdefault
0\tunspec
#
# local
#
#1\tinr.ruhep\n"""

_RT_CUSTOM = _RT_DEFAULT + "# Custom\n10\tcustom # Custom table\n20\ttable1\n"

_BASE_IFACE_CFG = """
  -
    type: interface
    name: em1
  -
    type: interface
    name: eno2
    addresses:
     - ip_netmask: 2001:abc:a::2/64
     - ip_netmask: 192.168.1.2/24
    dispatch:
        post-activation: |
            /sbin/sysctl -w net.ipv6.conf.em1.keep_addr_on_down=1 #SYSCTL
"""

_BASE_IFACE_CFG_APPLIED = """
  em1:
    name: em1
    type: ethernet
    state: up
    ethernet:
      sr-iov:
        total-vfs: 0
    ipv4:
      enabled: false
      dhcp: False
    ipv6:
      enabled: false
      dhcp: False
      autoconf: False
  eno2:
    name: eno2
    type: ethernet
    state: up
    ethernet:
      sr-iov:
        total-vfs: 0
    ipv4:
      address:
      - ip: 192.168.1.2
        prefix-length: 24
      dhcp: false
      enabled: true
    ipv6:
      address:
      - ip: 2001:abc:a::2
        prefix-length: 64
      autoconf: false
      dhcp: false
      enabled: true
    dispatch:
        post-activation: |
            /sbin/sysctl -w net.ipv6.conf.eno2.keep_addr_on_down=1 #SYSCTL
"""


_BASE_NMSTATE_IFACE_CFG = """- name: em1
  type: ethernet
  state: up
"""

_NO_IP = _BASE_NMSTATE_IFACE_CFG + """
  ethernet:
    sr-iov:
      total-vfs: 0
  ipv4:
    enabled: false
    dhcp: False
  ipv6:
    enabled: false
    dhcp: False
    autoconf: False
"""

_NO_IP_WO_SRIOV = _BASE_NMSTATE_IFACE_CFG + """
  ethernet: {}
  ipv4:
    enabled: false
    dhcp: False
  ipv6:
    enabled: false
    dhcp: False
    autoconf: False
"""

_V4_NMCFG = _BASE_NMSTATE_IFACE_CFG + """
  ethernet:
    sr-iov:
      total-vfs: 0
  ipv6:
    enabled: False
    autoconf: False
    dhcp: False
  ipv4:
    enabled: True
    dhcp: False
    address:
    - ip: 192.168.1.2
      prefix-length: 24
"""

_V4_NMCFG_MULTIPLE = _V4_NMCFG + """    - ip: 192.168.2.2
      prefix-length: 32
    - ip: 10.0.0.2
      prefix-length: 8
"""

_V4_NMCFG_MAPPED = _V4_NMCFG + """
  802-3-Ethernet.cloned-mac-address: a1:b2:c3:d4:e5
"""

_V4_V6_NMCFG = _BASE_NMSTATE_IFACE_CFG + """  ipv6:
    enabled: True
    autoconf: False
    dhcp: False
    address:
    - ip: 2001:abc:a::2
      prefix-length: 64
  ipv4:
    enabled: True
    dhcp: False
    address:
    - ip: 192.168.1.2
      prefix-length: 24
  ethernet:
    sr-iov:
      total-vfs: 0
  dispatch:
      post-activation: |
          /sbin/sysctl -w net.ipv6.conf.em1.keep_addr_on_down=1 #SYSCTL
"""

_V6_NMCFG = _BASE_NMSTATE_IFACE_CFG + """
  ethernet:
    sr-iov:
      total-vfs: 0
  dispatch:
      post-activation: |
          /sbin/sysctl -w net.ipv6.conf.em1.keep_addr_on_down=1 #SYSCTL
  ipv4:
    enabled: False
    dhcp: False
  ipv6:
    enabled: True
    autoconf: False
    dhcp: False
    address:
    - ip: "2001:abc:a::"
      prefix-length: 64
"""

_V6_NMCFG_MULTIPLE = _V6_NMCFG + """    - ip: 2001:abc:b::1
      prefix-length: 64
    - ip: 2001:abc:c::2
      prefix-length: 96
"""


def stub_get_pci_address(ifname):
    pci_map = {"eth1": "0000:07:00.1",
               "eth2": "0000:08:00.1",
               "sriov:eth1:2": "0000:07:02.1",
               "sriov:eth1:3": "0000:07:03.1",
               "sriov:eth1:4": "0000:07:04.1",
               "sriov:eth2:2": "0000:08:02.1",
               "sriov:eth2:3": "0000:08:03.1",
               "sriov:eth2:4": "0000:08:04.1"}
    return pci_map.get(ifname, None)


def stub_get_dpdk_pci_address(ifname):
    pci_map = {"eth1": "0000:07:00.1",
               "eth2": "0000:08:00.1"}
    return pci_map.get(ifname, None)


def generate_random_mac(name):
    # Generate 6 random bytes
    mac = [random.randint(0, 255) for _ in range(6)]
    mac[0] &= 0xFE
    mac_address = ':'.join(f'{byte:02x}' for byte in mac)
    return mac_address


class TestNmstateNetConfig(base.TestCase):
    def setUp(self):
        super(TestNmstateNetConfig, self).setUp()
        common.set_noop(True)
        common.DPDK_MAPPING_FILE = '/tmp/dpdk_mapping.yaml'
        common.SRIOV_CONFIG_FILE = '/tmp/sriov_config.yaml'

        def sysctl_path_stub():
            return "/sbin/sysctl"
        self.stub_out('os_net_config.utils.sysctl_path',
                      sysctl_path_stub)

        self.stub_out("os_net_config.common.interface_mac",
                      generate_random_mac)
        impl_nmstate.DISPATCHER_SCRIPT_PREFIX = ""
        impl_nmstate._VF_BIND_DRV_SCRIPT = (
            'dpdk_vfs="{dpdk_vfs}"\n'
            'linux_vfs="{linux_vfs}"')

        def show_running_info_stub():
            running_info_path = os.path.join(
                os.path.dirname(__file__),
                'environment/netinfo_running_info_1.yaml')
            running_info = self.get_running_info(running_info_path)
            return running_info
        self.stub_out('libnmstate.netinfo.show_running_config',
                      show_running_info_stub)

        self.temp_route_table_file = tempfile.NamedTemporaryFile()
        self.provider = impl_nmstate.NmstateNetConfig()

        def get_totalvfs_stub(iface_name):
            return 10
        self.stub_out('os_net_config.utils.get_totalvfs',
                      get_totalvfs_stub)

        def stub_is_ovs_installed():
            return True
        self.stub_out('os_net_config.utils.is_ovs_installed',
                      stub_is_ovs_installed)

        def test_route_table_path():
            return self.temp_route_table_file.name
        self.stub_out(
            'os_net_config.impl_nmstate.route_table_config_path',
            test_route_table_path)
        utils.write_config(self.temp_route_table_file.name, _RT_CUSTOM)

        def update_sriov_pf_map_stub(ifname, numvfs, noop, promisc=None,
                                     link_mode='legacy', vdpa=False,
                                     drivers_autoprobe=True,
                                     steering_mode=None, lag_candidate=None,
                                     pci_address=None, mac_address=None):
            return
        self.stub_out('os_net_config.utils.update_sriov_pf_map',
                      update_sriov_pf_map_stub)

        def update_sriov_vf_map_stub(pf_name, vfid, vf_name, vlan_id=0,
                                     qos=0, spoofcheck=None, trust=None,
                                     state=None, macaddr=None, promisc=None,
                                     pci_address=None, min_tx_rate=0,
                                     max_tx_rate=0, driver=None):
            return
        self.stub_out('os_net_config.utils.update_sriov_vf_map',
                      update_sriov_vf_map_stub)

        def test_get_vf_devname(device, vfid):
            return device + '_' + str(vfid)
        self.stub_out('os_net_config.utils.get_vf_devname',
                      test_get_vf_devname)

        def test_bind_dpdk_interfaces(ifname, driver, noop):
            return
        self.stub_out('os_net_config.utils.bind_dpdk_interfaces',
                      test_bind_dpdk_interfaces)

    def tearDown(self):
        super(TestNmstateNetConfig, self).tearDown()
        if os.path.isfile(common.SRIOV_CONFIG_FILE):
            os.remove(common.SRIOV_CONFIG_FILE)
        if os.path.isfile(common.DPDK_MAPPING_FILE):
            os.remove(common.DPDK_MAPPING_FILE)

    def get_running_info(self, yaml_file):
        with open(yaml_file) as f:
            data = yaml.load(f, Loader=yaml.SafeLoader)
            return data

    def get_interface_config(self, name='em1'):
        return self.provider.interface_data[name]

    def get_vlan_config(self, name):
        return self.provider.vlan_data[name]

    def get_bridge_config(self, name):
        return self.provider.bridge_data[name]

    def get_linuxbond_config(self, name='bond0'):
        return self.provider.linuxbond_data[name]

    def get_nmstate_ethtool_opts(self, name):
        data = {}
        iface = self.provider.interface_data[name]
        data[Ethernet.CONFIG_SUBTREE] = iface[Ethernet.CONFIG_SUBTREE]
        data[Ethtool.CONFIG_SUBTREE] = iface[Ethtool.CONFIG_SUBTREE]
        if 'dispatch' in iface.keys():
            data['dispatch'] = iface['dispatch']
        return data

    def get_dns_data(self):
        return self.provider.dns_data

    def get_route_table_config(self, name='custom', table_id=200):
        return self.provider.route_table_data.get(name, table_id)

    def get_rule_config(self):
        return self.provider.rules_data

    def get_route_config(self, name):
        return self.provider.route_data.get(name, '')

    def test_add_base_interface(self):
        interface = objects.Interface('em1')
        self.provider.add_interface(interface)
        self.assertEqual(yaml.safe_load(_NO_IP)[0],
                         self.get_interface_config())
        self.assertEqual('', self.get_route_config('em1'))

    def test_add_base_interface_without_sriov_caps(self):
        def get_totalvfs_stub(iface_name):
            return -1
        self.stub_out('os_net_config.utils.get_totalvfs',
                      get_totalvfs_stub)

        interface = objects.Interface('em1')
        self.provider.add_interface(interface)
        self.assertEqual(yaml.safe_load(_NO_IP_WO_SRIOV)[0],
                         self.get_interface_config())
        self.assertEqual('', self.get_route_config('em1'))

    def test_add_interface_with_v6(self):
        v6_addr = objects.Address('2001:abc:a::/64')
        interface = objects.Interface('em1', addresses=[v6_addr])
        self.provider.add_interface(interface)
        self.assertEqual(yaml.safe_load(_V6_NMCFG)[0],
                         self.get_interface_config())
        self.assertEqual('', self.get_route_config('em1'))

    def test_add_interface_with_v4_v6(self):
        addresses = [objects.Address('2001:abc:a::2/64'),
                     objects.Address('192.168.1.2/24')]
        interface = objects.Interface('em1', addresses=addresses)
        self.provider.add_interface(interface)
        self.assertEqual(yaml.safe_load(_V4_V6_NMCFG)[0],
                         self.get_interface_config())
        self.assertEqual('', self.get_route_config('em1'))

    def test_add_interface_with_v6_multiple(self):
        addresses = [objects.Address('2001:abc:a::/64'),
                     objects.Address('2001:abc:b::1/64'),
                     objects.Address('2001:abc:c::2/96')]
        interface = objects.Interface('em1', addresses=addresses)
        self.provider.add_interface(interface)
        self.assertEqual(yaml.safe_load(_V6_NMCFG_MULTIPLE)[0],
                         self.get_interface_config())
        self.assertEqual('', self.get_route_config('em1'))

    def test_interface_defroute(self):
        interface1 = objects.Interface('em1')
        interface2 = objects.Interface('em2', defroute=False)
        self.provider.add_interface(interface1)
        self.provider.add_interface(interface2)
        em1_config = """- name: em1
  type: ethernet
  state: up
  ethernet:
    sr-iov:
      total-vfs: 0
  ipv4:
    enabled: False
    dhcp: False
  ipv6:
    enabled: False
    autoconf: False
    dhcp: False
"""
        em2_config = """- name: em2
  type: ethernet
  state: up
  ethernet:
    sr-iov:
      total-vfs: 0
  ipv4:
    enabled: False
    auto-gateway: False
    dhcp: False
  ipv6:
    auto-gateway: False
    enabled: False
    autoconf: False
    dhcp: False
"""
        self.assertEqual(yaml.safe_load(em1_config)[0],
                         self.get_interface_config('em1'))
        self.assertEqual('', self.get_route_config('em1'))
        self.assertEqual(yaml.safe_load(em2_config)[0],
                         self.get_interface_config('em2'))
        self.assertEqual('', self.get_route_config('em2'))

    def test_interface_dns_server(self):
        interface1 = objects.Interface('em1', dns_servers=['1.2.3.4'])
        self.provider.add_interface(interface1)
        em1_config = """- name: em1
  type: ethernet
  state: up
  ethernet:
    sr-iov:
      total-vfs: 0
  ipv4:
    auto-dns: False
    enabled: False
    dhcp: False
  ipv6:
    auto-dns: False
    enabled: False
    autoconf: False
    dhcp: False
"""
        test_dns_config1 = """
  server:
    - 1.2.3.4
  domain: []
"""
        self.assertEqual(yaml.safe_load(em1_config)[0],
                         self.get_interface_config('em1'))

        self.assertEqual(yaml.safe_load(test_dns_config1),
                         self.get_dns_data())
        interface2 = objects.Interface('em2',
                                       dns_servers=['1.2.3.4',
                                                    '2001:4860:4860::8888'],
                                       domain=['example.com', 'server.org'])
        self.provider.add_interface(interface2)
        test_dns_config2 = """
  server:
    - 1.2.3.4
    - 2001:4860:4860::8888
  domain:
    - example.com
    - server.org
"""
        self.assertEqual(yaml.safe_load(test_dns_config2),
                         self.get_dns_data())
        interface3 = objects.Interface('em3',
                                       dns_servers=['1.2.3.4',
                                                    '2001:4860:4860::8888'],
                                       domain='testdomain.com')
        self.provider.add_interface(interface3)
        test_dns_config3 = """
  server:
    - 1.2.3.4
    - 2001:4860:4860::8888
  domain:
    - example.com
    - server.org
    - testdomain.com
"""
        self.assertEqual(yaml.safe_load(test_dns_config3),
                         self.get_dns_data())

    def test_ethtool_opts(self):
        interface1 = objects.Interface('em1',
                                       ethtool_opts='speed 1000 duplex full '
                                                    'autoneg on')
        interface2 = objects.Interface('em2',
                                       ethtool_opts='--set-ring \
                                       ${DEVICE} rx 1024 tx 1024')
        interface3 = objects.Interface('em3',
                                       ethtool_opts='-G $DEVICE '
                                       'rx 1024 tx 1024;'
                                       '-A ${DEVICE} autoneg on;'
                                       '--offload ${DEVICE} '
                                       'hw-tc-offload on')
        interface4 = objects.Interface('em4',
                                       ethtool_opts='-K ${DEVICE} '
                                       'hw-tc-offload on;'
                                       '-C ${DEVICE} adaptive-rx off '
                                       'adaptive-tx off')
        interface5 = objects.Interface('em5',
                                       ethtool_opts='-s ${DEVICE} speed '
                                       '100 duplex half autoneg off')
        # Mismatch in device name
        interface6 = objects.Interface('em6',
                                       ethtool_opts='-s em3 speed 100 '
                                       'duplex half autoneg off')
        # Handled with dispatcher scripts -U
        interface7 = objects.Interface('em7',
                                       ethtool_opts='-U ${DEVICE} '
                                       'flow-type tcp4 tos 1 action 10')
        # Handled with dispatcher scripts --set-priv-flags
        interface10 = objects.Interface(
            'em10',
            ethtool_opts='--set-priv-flags $DEVICE disable-fw-lldp off'
            )
        # Unsupported option `advertise`
        interface8 = objects.Interface('em8',
                                       ethtool_opts='advertise 0x100000')
        # Unsupported format
        interface9 = objects.Interface('em9',
                                       ethtool_opts='s $DEVICE rx 78')

        self.provider.add_interface(interface1)
        self.provider.add_interface(interface2)
        self.provider.add_interface(interface3)
        self.provider.add_interface(interface4)
        self.provider.add_interface(interface5)
        self.provider.add_interface(interface7)
        self.provider.add_interface(interface10)

        em1_config = """
  - ethernet:
      speed: 1000
      duplex: full
      auto-negotiation: true
      sr-iov:
        total-vfs: 0
    ethtool: {}
"""
        em2_config = """
  - ethernet:
      sr-iov:
        total-vfs: 0
    ethtool:
      ring:
        rx: 1024
        tx: 1024
"""
        em3_config = """
  - ethernet:
      sr-iov:
        total-vfs: 0
    ethtool:
      ring:
        rx: 1024
        tx: 1024
      pause:
        autoneg: true
      feature:
        hw-tc-offload: true
"""
        em4_config = """
  - ethernet:
      sr-iov:
        total-vfs: 0
    ethtool:
      feature:
        hw-tc-offload: true
      coalesce:
        adaptive-rx: false
        adaptive-tx: false
"""
        em5_config = """
  - ethernet:
      speed: 100
      duplex: half
      auto-negotiation: false
      sr-iov:
        total-vfs: 0
    ethtool: {}
"""
        em7_config = """
  - ethernet:
      sr-iov:
        total-vfs: 0
    ethtool: {}
    dispatch:
        post-activation: |
            /sbin/ethtool -U $1 flow-type tcp4 tos 1 action 10 #ETHTOOL
"""
        em10_config = """
  - ethernet:
      sr-iov:
        total-vfs: 0
    ethtool: {}
    dispatch:
        post-activation: |
            /sbin/ethtool --set-priv-flags $1 disable-fw-lldp off #ETHTOOL
"""
        self.assertEqual(yaml.safe_load(em1_config)[0],
                         self.get_nmstate_ethtool_opts('em1'))
        self.assertEqual(yaml.safe_load(em2_config)[0],
                         self.get_nmstate_ethtool_opts('em2'))
        self.assertEqual(yaml.safe_load(em3_config)[0],
                         self.get_nmstate_ethtool_opts('em3'))
        self.assertEqual(yaml.safe_load(em4_config)[0],
                         self.get_nmstate_ethtool_opts('em4'))
        self.assertEqual(yaml.safe_load(em5_config)[0],
                         self.get_nmstate_ethtool_opts('em5'))
        self.assertRaises(os_net_config.ConfigurationError,
                          self.provider.add_interface,
                          interface6)
        self.assertEqual(yaml.safe_load(em7_config)[0],
                         self.get_nmstate_ethtool_opts('em7'))
        self.assertEqual(yaml.safe_load(em10_config)[0],
                         self.get_nmstate_ethtool_opts('em10'))
        self.assertRaises(os_net_config.ConfigurationError,
                          self.provider.add_interface,
                          interface8)
        self.assertRaises(os_net_config.ConfigurationError,
                          self.provider.add_interface,
                          interface9)

    def test_add_route_table(self):
        route_table1 = objects.RouteTable('table1', 200)
        route_table2 = objects.RouteTable('table2', '201')
        self.provider.add_route_table(route_table1)
        self.provider.add_route_table(route_table2)
        self.assertEqual("table1", self.get_route_table_config(200))
        self.assertEqual("table2", self.get_route_table_config(201))

    def test_add_route_with_table(self):
        expected_route_table = """
            - destination: 172.19.0.0/24
              next-hop-address: 192.168.1.1
              next-hop-interface: em1
              table-id: 200
            - destination: 172.20.0.0/24
              next-hop-address: 192.168.1.1
              next-hop-interface: em1
              table-id: 201
            - destination: 172.21.0.0/24
              next-hop-address: 192.168.1.1
              next-hop-interface: em1
              table-id: 200
        """
        expected_rule = """
            - ip-from: 192.0.2.0/24
              route-table: 200
        """
        route_table1 = objects.RouteTable('table1', 200)
        self.provider.add_route_table(route_table1)

        route_rule1 = objects.RouteRule('from 192.0.2.0/24 table 200',
                                        'test comment')
        # Test route table by name
        route1 = objects.Route('192.168.1.1', '172.19.0.0/24', False,
                               route_table="table1")
        # Test that table specified in route_options takes precedence
        route2 = objects.Route('192.168.1.1', '172.20.0.0/24', False,
                               'table 201', route_table=200)
        # Test route table specified by integer ID
        route3 = objects.Route('192.168.1.1', '172.21.0.0/24', False,
                               route_table=200)
        v4_addr = objects.Address('192.168.1.2/24')
        interface = objects.Interface('em1', addresses=[v4_addr],
                                      routes=[route1, route2, route3],
                                      rules=[route_rule1])
        self.provider.add_interface(interface)

        self.assertEqual(yaml.safe_load(expected_route_table),
                         self.get_route_config('em1'))
        self.assertEqual(yaml.safe_load(expected_rule),
                         self.get_rule_config())

    def test_ip_rules(self):
        expected_rule = """
            - action: blackhole
              ip-from: 172.19.40.0/24
              route-table: 200
            - action: unreachable
              iif: em1
              ip-from: 192.168.1.0/24
            - family: ipv4
              iif: em1
              route-table: 200
        """
        rule1 = objects.RouteRule(
            'add blackhole from 172.19.40.0/24 table 200', 'rule1')
        rule2 = objects.RouteRule(
            'add unreachable iif em1 from 192.168.1.0/24', 'rule2')
        rule3 = objects.RouteRule('iif em1 table 200', 'rule3')
        v4_addr = objects.Address('192.168.1.2/24')
        interface = objects.Interface('em1', addresses=[v4_addr],
                                      rules=[rule1, rule2, rule3])
        self.provider.add_interface(interface)

        self.assertEqual(yaml.safe_load(expected_rule),
                         self.get_rule_config())

    def test_network_with_routes(self):
        expected_route_table = """
            - destination: 0.0.0.0/0
              metric: 10
              next-hop-address: 192.168.1.1
              next-hop-interface: em1
            - destination: 172.19.0.0/24
              next-hop-address: 192.168.1.1
              next-hop-interface: em1
            - destination: 172.20.0.0/24
              metric: 100
              next-hop-address: 192.168.1.5
              next-hop-interface: em1
        """
        route1 = objects.Route('192.168.1.1', default=True,
                               route_options="metric 10")
        route2 = objects.Route('192.168.1.1', '172.19.0.0/24')
        route3 = objects.Route('192.168.1.5', '172.20.0.0/24',
                               route_options="metric 100")
        v4_addr = objects.Address('192.168.1.2/24')
        interface = objects.Interface('em1', addresses=[v4_addr],
                                      routes=[route1, route2, route3])
        self.provider.add_interface(interface)
        self.assertEqual(yaml.safe_load(expected_route_table),
                         self.get_route_config('em1'))

    def test_network_with_route_via_device(self):
        expected_route_table = """
               - destination: 0.0.0.0/0
                 metric: 10
                 next-hop-interface: em1
               - destination: 172.22.0.0/24
                 metric: 100
                 next-hop-address: 172.20.0.1
                 next-hop-interface: em1
           """
        route1 = objects.Route("self", ip_netmask='0.0.0.0/0',
                               route_options="metric 10")
        route2 = objects.Route('172.20.0.1', '172.22.0.0/24',
                               route_options="metric 100")
        v4_addr = objects.Address('192.168.1.2/24')
        interface = objects.Interface('em1', addresses=[v4_addr],
                                      routes=[route1, route2])
        self.provider.add_interface(interface)
        self.assertEqual(yaml.safe_load(expected_route_table),
                         self.get_route_config('em1'))

    def test_network_with_ipv6_routes_via_device(self):
        expected_route_table = """
            - destination: ::/0
              next-hop-interface: em1
            - destination: beaf::/56
              next-hop-address: beaf::1
              next-hop-interface: em1
        """
        route4 = objects.Route('self', ip_netmask='::/0')
        route5 = objects.Route('beaf::1', ip_netmask='beaf::/56')
        v4_addr = objects.Address('192.168.1.2/24')
        v6_addr = objects.Address('2001:abc:a::/64')
        interface = objects.Interface('em1', addresses=[v4_addr, v6_addr],
                                      routes=[route4, route5])

        self.provider.add_interface(interface)
        self.assertEqual(yaml.safe_load(expected_route_table),
                         self.get_route_config('em1'))

    def test_network_with_ipv6_routes(self):
        expected_route_table = """
            - destination: ::/0
              next-hop-address: 2001:db8::1
              next-hop-interface: em1
            - destination: 2001:db8:dead:beef:cafe::/56
              next-hop-address: fd00:fd00:2000::1
              next-hop-interface: em1
            - destination: 2001:db8:dead:beff::/64
              metric: 100
              next-hop-address: fd00:fd00:2000::1
              next-hop-interface: em1
        """
        route4 = objects.Route('2001:db8::1', default=True)
        route5 = objects.Route('fd00:fd00:2000::1',
                               '2001:db8:dead:beef:cafe::/56')
        route6 = objects.Route('fd00:fd00:2000::1',
                               '2001:db8:dead:beff::/64',
                               route_options="metric 100")
        v4_addr = objects.Address('192.168.1.2/24')
        v6_addr = objects.Address('2001:abc:a::/64')
        interface = objects.Interface('em1', addresses=[v4_addr, v6_addr],
                                      routes=[route4, route5, route6])
        self.provider.add_interface(interface)
        self.assertEqual(yaml.safe_load(expected_route_table),
                         self.get_route_config('em1'))

    def test_linux_bond(self):
        expected_config1 = """
      name: bond0
      type: bond
      state: up
      link-aggregation:
          mode: active-backup
          port:
              - em1
              - em2
          options:
              primary: em1
      ipv4:
          auto-dns: True
          enabled: True
          dhcp: True
          auto-routes: True
          auto-gateway: True
      ipv6:
          enabled: False
          autoconf: False
          dhcp: False
    """
        expected_em1_cfg = """
        name: em1
        state: up
        ethernet:
            sr-iov:
              total-vfs: 0
        ipv4:
            dhcp: False
            enabled: False
        ipv6:
            autoconf: False
            dhcp: False
            enabled: False
        type: ethernet
        """
        expected_em2_cfg = """
        name: em2
        state: up
        ethernet:
            sr-iov:
              total-vfs: 0
        ipv4:
            dhcp: False
            enabled: False
        ipv6:
            autoconf: False
            dhcp: False
            enabled: False
        type: ethernet
        """

        expected_config2 = """
      name: bond1
      type: bond
      state: up
      link-aggregation:
          mode: 802.3ad
          options:
              miimon: 100
              updelay: 1000
              lacp_rate: slow
          port:
              - em3
              - em4
      ipv4:
          auto-dns: True
          enabled: True
          dhcp: True
          auto-routes: True
          auto-gateway: True
      ipv6:
          enabled: False
          autoconf: False
          dhcp: False
    """
        interface1 = objects.Interface('em1', primary=True)
        interface2 = objects.Interface('em2')
        bond = objects.LinuxBond('bond0', use_dhcp=True,
                                 members=[interface1, interface2])
        self.provider.add_linux_bond(bond)
        self.provider.add_interface(interface1)
        self.provider.add_interface(interface2)
        self.assertEqual(yaml.safe_load(expected_config1),
                         self.get_linuxbond_config('bond0'))
        self.assertEqual(yaml.safe_load(expected_em1_cfg),
                         self.get_interface_config('em1'))
        self.assertEqual(yaml.safe_load(expected_em2_cfg),
                         self.get_interface_config('em2'))

        # primary interface is used only for active-slave bonds
        interface1 = objects.Interface('em3')
        interface2 = objects.Interface('em4', primary=True)
        bond = objects.LinuxBond('bond1', use_dhcp=True,
                                 members=[interface1, interface2],
                                 bonding_options="mode=802.3ad "
                                 "lacp_rate=slow updelay=1000 miimon=100")
        self.provider.add_linux_bond(bond)
        self.assertEqual(yaml.safe_load(expected_config2),
                         self.get_linuxbond_config('bond1'))

    def test_network_ovs_bridge_with_dhcp(self):
        expected_brctl_p_cfg = """
        name: br-ctlplane
        state: up
        type: ovs-interface
        ipv4:
            auto-dns: True
            auto-gateway: True
            auto-routes: True
            dhcp: True
            enabled: True
        ipv6:
            autoconf: False
            dhcp: False
            enabled: False
        """
        expected_brctl_cfg = """
        name: br-ctlplane
        type: ovs-bridge
        bridge:
            allow-extra-patch-ports: True
            options:
                fail-mode: standalone
                mcast-snooping-enable: False
                rstp: False
                stp: False
            port:
                - name: em1
                - name: br-ctlplane
        ovs-db:
            external_ids: {}
            other_config: { mac-table-size: 50000 }
        state: up
        """

        interface = objects.Interface('em1')
        bridge = objects.OvsBridge('br-ctlplane', use_dhcp=True,
                                   members=[interface])
        self.provider.add_bridge(bridge)
        self.assertEqual(yaml.safe_load(expected_brctl_p_cfg),
                         self.get_interface_config('br-ctlplane-if'))
        self.assertEqual(yaml.safe_load(expected_brctl_cfg),
                         self.get_bridge_config('br-ctlplane'))

    def test_network_ovs_bridge_with_bond(self):
        expected_brctl2_p_cfg = """
        name: br-ctlplane2
        state: up
        type: ovs-interface
        ipv4:
            auto-dns: True
            auto-gateway: True
            auto-routes: True
            dhcp: True
            enabled: True
        ipv6:
            autoconf: False
            dhcp: False
            enabled: False
        """
        expected_brctl2_cfg = """
        name: br-ctlplane2
        type: ovs-bridge
        bridge:
            allow-extra-patch-ports: True
            options:
                fail-mode: standalone
                mcast-snooping-enable: False
                rstp: False
                stp: False
            port:
                - name: bond0
                  link-aggregation:
                      mode: active-backup
                      port:
                          - name: em2
                          - name: em3
                      ovs-db:
                          other_config:
                              bond-primary: em2
                - name: br-ctlplane2
        ovs-db:
            external_ids: {}
            other_config: { mac-table-size: 50000 }
        state: up
        """

        interface1 = objects.Interface('em2')
        interface2 = objects.Interface('em3')
        bond = objects.OvsBond('bond0', members=[interface1, interface2])
        bridge = objects.OvsBridge('br-ctlplane2', use_dhcp=True,
                                   members=[bond])
        self.provider.add_bridge(bridge)
        self.assertEqual(yaml.safe_load(expected_brctl2_p_cfg),
                         self.get_interface_config('br-ctlplane2-if'))
        self.assertEqual(yaml.safe_load(expected_brctl2_cfg),
                         self.get_bridge_config('br-ctlplane2'))

    def test_network_ovs_bridge_with_bond_options(self):
        expected_brctl2_cfg = """
        name: br-ctlplane2
        type: ovs-bridge
        bridge:
            allow-extra-patch-ports: True
            options:
                fail-mode: standalone
                mcast-snooping-enable: False
                rstp: False
                stp: False
            port:
                - name: bond0
                  link-aggregation:
                      bond-updelay: 1000
                      mode: balance-slb
                      ovs-db:
                          other_config:
                              bond-detect-mode: miimon
                              bond-miimon-interval: 100
                              bond-rebalance-interval: 10000
                              bond-primary: em2
                              lacp-fallback-ab: true
                              lacp-time: fast
                      port:
                          - name: em2
                          - name: em3
                - name: br-ctlplane2
        state: up
        ovs-db:
            external_ids: {}
            other_config: { mac-table-size: 50000 }
        """
        interface1 = objects.Interface('em2')
        interface2 = objects.Interface('em3')

        ovs_options = 'bond_mode=balance-slb ' \
                      'other-config:lacp-fallback-ab=true ' \
                      'other-config:lacp-time=fast ' \
                      'other_config:bond-detect-mode=miimon ' \
                      'other_config:bond-miimon-interval=100 ' \
                      'bond_updelay=1000 ' \
                      'other_config:bond-rebalance-interval=10000'
        bond = objects.OvsBond('bond0', members=[interface1, interface2],
                               ovs_options=ovs_options)
        bridge = objects.OvsBridge('br-ctlplane2', use_dhcp=True,
                                   members=[bond])
        self.provider.add_bridge(bridge)
        self.assertEqual(yaml.safe_load(expected_brctl2_cfg),
                         self.get_bridge_config('br-ctlplane2'))

    def test_network_ovs_bridge_with_ovs_extra(self):
        expected_brctl2_cfg = """
        name: br-ctlplane2
        type: ovs-bridge
        bridge:
            allow-extra-patch-ports: True
            options:
                fail-mode: standalone
                mcast-snooping-enable: True
                rstp: True
                stp: True
            port:
                - name: bond0
                  link-aggregation:
                      mode: balance-slb
                      port:
                          - name: em2
                          - name: em3
                      ovs-db:
                          other_config:
                              bond-primary: em2
                              zig: zag
                          external_ids:
                              foo: bar
                - name: br-ctlplane2
                  vlan:
                      tag: 70
                      mode: access
        ovs-db:
            external_ids:
                bridge-id: br-ctlplane
            other_config:
                mac-table-size: 50000
                stp-priority: '0x7800'
        state: up
        """
        interface1 = objects.Interface('em2')
        interface2 = objects.Interface('em3')
        ovs_extra = [
            "br-set-external-id br-ctlplane2 bridge-id br-ctlplane",
            "set bridge {name} stp_enable=true rstp_enable=true",
            "set bridge {name} fail_mode=standalone",
            "set bridge br-ctlplane2 mcast_snooping_enable=true",
            "set Bridge {name} other_config:stp-priority=0x7800",
            "set port {name} tag=70"]

        ovs_extra_b = ["set port {name} external-ids:foo=bar",
                       "set port {name} other_config:zig=zag"]
        ovs_options = 'bond_mode=balance-slb'
        bond = objects.OvsBond('bond0', members=[interface1, interface2],
                               ovs_options=ovs_options, ovs_extra=ovs_extra_b)
        bridge = objects.OvsBridge('br-ctlplane2', use_dhcp=True,
                                   members=[bond], ovs_extra=ovs_extra)
        self.provider.add_bridge(bridge)
        self.assertEqual(yaml.safe_load(expected_brctl2_cfg),
                         self.get_bridge_config('br-ctlplane2'))

    def test_network_ovs_bridge_without_bond_with_ovs_extra(self):
        expected_brctl2_cfg = """
        name: br-ctlplane2
        type: ovs-bridge
        bridge:
            allow-extra-patch-ports: True
            options:
                fail-mode: standalone
                mcast-snooping-enable: True
                rstp: True
                stp: True
            port:
                - name: em2
                - name: em3
                - name: br-ctlplane2
                  vlan:
                      tag: 70
                      mode: access
        ovs-db:
            external_ids:
                bridge-id: br-ctlplane
            other_config:
                mac-table-size: 50000
                stp-priority: '0x7800'
        state: up
        """

        expected_em2_cfg = """
        name: em2
        state: up
        ethernet:
            sr-iov:
              total-vfs: 0
        ipv4:
            dhcp: False
            enabled: False
        ipv6:
            autoconf: False
            dhcp: False
            enabled: False
        type: ethernet
        ovs-db:
            external_ids:
                foo: bar
        """

        ovs_extra_if = ["set interface {name} external-ids:foo=bar"]
        interface1 = objects.Interface('em2', ovs_extra=ovs_extra_if)
        interface2 = objects.Interface('em3', ovs_extra=ovs_extra_if)
        ovs_extra = [
            "br-set-external-id br-ctlplane2 bridge-id br-ctlplane",
            "set bridge {name} stp_enable=true rstp_enable=true",
            "set bridge {name} fail_mode=standalone",
            "set bridge br-ctlplane2 mcast_snooping_enable=true",
            "set Bridge {name} other_config:stp-priority=0x7800",
            "set port {name} tag=70"]

        bridge = objects.OvsBridge('br-ctlplane2', use_dhcp=True,
                                   members=[interface1, interface2],
                                   ovs_extra=ovs_extra)
        self.provider.add_bridge(bridge)
        self.provider.add_interface(interface1)
        self.assertEqual(yaml.safe_load(expected_brctl2_cfg),
                         self.get_bridge_config('br-ctlplane2'))
        self.assertEqual(yaml.safe_load(expected_em2_cfg),
                         self.get_interface_config('em2'))

    def test_network_ovs_bridge_with_linux_bond(self):
        expected_brctl2_cfg = """
        name: br-ctlplane2
        type: ovs-bridge
        bridge:
            allow-extra-patch-ports: True
            options:
                fail-mode: standalone
                mcast-snooping-enable: False
                rstp: False
                stp: False
            port:
                - name: bond0
                - name: br-ctlplane2
        ovs-db:
            external_ids: {}
            other_config: {}
        state: up
        ovs-db:
            external_ids: {}
            other_config: { mac-table-size: 50000 }
        """
        expected_bond0_config = """
      name: bond0
      type: bond
      state: up
      link-aggregation:
          mode: active-backup
          port:
              - em3
              - em2
          options:
              primary: em3
      ipv4:
          enabled: False
          dhcp: False
      ipv6:
          enabled: False
          autoconf: False
          dhcp: False
    """
        interface1 = objects.Interface('em2')
        interface2 = objects.Interface('em3', primary=True)

        bond = objects.LinuxBond('bond0', members=[interface1, interface2])
        bridge = objects.OvsBridge('br-ctlplane2', use_dhcp=True,
                                   members=[bond])
        self.provider.add_bridge(bridge)
        self.provider.add_linux_bond(bond)
        self.assertEqual(yaml.safe_load(expected_brctl2_cfg),
                         self.get_bridge_config('br-ctlplane2'))
        self.assertCountEqual(yaml.safe_load(expected_bond0_config),
                              self.get_linuxbond_config('bond0'))

    def test_vlan_interface(self):
        expected_vlan1_cfg = """
        name: vlan502
        type: vlan
        vlan:
            base-iface: em2
            id: 502
        state: up
        ipv4:
            dhcp: false
            enabled: false
        ipv6:
            address:
                - ip: "2001:abc:a::"
                  prefix-length: 64
            autoconf: false
            dhcp: false
            enabled: true
        dispatch:
            post-activation: |
                /sbin/sysctl -w net.ipv6.conf.%s.keep_addr_on_down=1 #SYSCTL
        """ % 'vlan502'
        v6_addr = objects.Address('2001:abc:a::/64')
        vlan1 = objects.Vlan('em2', 502, addresses=[v6_addr])
        self.provider.add_vlan(vlan1)
        self.assertEqual(yaml.safe_load(expected_vlan1_cfg),
                         self.get_vlan_config('vlan502'))

    def test_vlan_as_interface(self):
        expected_vlan1_cfg = """
        name: em2.502
        type: vlan
        vlan:
            base-iface: em2
            id: 502
        state: up
        ipv4:
            dhcp: false
            enabled: false
        ipv6:
            address:
                - ip: "2001:abc:a::"
                  prefix-length: 64
            autoconf: false
            dhcp: false
            enabled: true
        dispatch:
            post-activation: |
                /sbin/sysctl -w net.ipv6.conf.%s.keep_addr_on_down=1 #SYSCTL
        """ % 'em2.502'
        v6_addr = objects.Address('2001:abc:a::/64')
        em2 = objects.Interface('em2.502', addresses=[v6_addr])
        self.provider.add_interface(em2)
        self.assertEqual(yaml.safe_load(expected_vlan1_cfg),
                         self.get_vlan_config('em2.502'))

    def test_add_vlan_ovs(self):
        expected_vlan1_cfg = """
        name: vlan5
        ipv4:
            dhcp: false
            enabled: false
        ipv6:
            autoconf: false
            dhcp: false
            enabled: false
        state: up
        type: ovs-interface
        """
        expected_bridge_cfg = """
        name: br-ctlplane
        bridge:
            allow-extra-patch-ports: True
            options:
                fail-mode: standalone
                mcast-snooping-enable: false
                rstp: false
                stp: false
            port:
                - name: em2
                - name: vlan5
                  vlan:
                      mode: access
                      tag: 5
                - name: br-ctlplane
        ovs-db:
            external_ids: {}
            other_config: { mac-table-size: 50000 }
        state: up
        type: ovs-bridge
        """
        interface1 = objects.Interface('em2')
        vlan = objects.Vlan(None, 5)
        bridge = objects.OvsBridge('br-ctlplane', use_dhcp=True,
                                   members=[interface1, vlan])
        self.provider.add_bridge(bridge)
        self.provider.add_vlan(vlan)
        self.assertEqual(yaml.safe_load(expected_vlan1_cfg),
                         self.get_vlan_config('vlan5'))
        self.assertEqual(yaml.safe_load(expected_bridge_cfg),
                         self.get_bridge_config('br-ctlplane'))

    def test_add_vlan_mtu_1500(self):
        expected_vlan1_cfg = """
        name: vlan5
        type: vlan
        vlan:
            base-iface: em1
            id: 5
        state: up
        mtu: 1500
        ipv4:
            dhcp: false
            enabled: false
        ipv6:
            autoconf: false
            dhcp: false
            enabled: false
        """
        vlan = objects.Vlan('em1', 5, mtu=1500)
        self.provider.add_vlan(vlan)
        self.assertEqual(yaml.safe_load(expected_vlan1_cfg),
                         self.get_vlan_config('vlan5'))

    def test_add_ovs_bridge_with_vlan(self):
        expected_vlan1_cfg = """
        name: vlan5
        ipv4:
            dhcp: false
            enabled: false
        ipv6:
            autoconf: false
            dhcp: false
            enabled: false
        state: up
        type: ovs-interface
        """
        expected_bridge_cfg = """
        name: br-ctlplane
        bridge:
            allow-extra-patch-ports: True
            options:
                fail-mode: standalone
                mcast-snooping-enable: false
                rstp: false
                stp: false
            port:
                - name: vlan5
                  vlan:
                      mode: access
                      tag: 5
                - name: br-ctlplane
        ovs-db:
            external_ids: {}
            other_config: { mac-table-size: 50000 }
        state: up
        type: ovs-bridge
        """
        vlan = objects.Vlan('em2', 5)
        bridge = objects.OvsBridge('br-ctlplane', use_dhcp=True,
                                   members=[vlan])
        self.provider.add_vlan(vlan)
        self.provider.add_bridge(bridge)
        self.assertEqual(yaml.safe_load(expected_bridge_cfg),
                         self.get_bridge_config('br-ctlplane'))
        self.assertEqual(yaml.safe_load(expected_vlan1_cfg),
                         self.get_vlan_config('vlan5'))

    def test_add_ovs_patch_port_to_bridge(self):
        expected_bridge_cfg = """
        name: br-phys-0
        bridge:
           allow-extra-patch-ports: True
           options:
              fail-mode: standalone
              mcast-snooping-enable: false
              rstp: false
              stp: false
           port:
             - name: physnet0-br-ex-patch
             - name: br-phys-0
        ovs-db:
           external_ids: {}
           other_config: { mac-table-size: 50000 }
        state: up
        type: ovs-bridge
        """
        expected_bridge_ex_cfg = """
        name: br-ex
        bridge:
           allow-extra-patch-ports: True
           options:
              fail-mode: standalone
              mcast-snooping-enable: false
              rstp: false
              stp: false
           port:
             - name: br-ex-physnet0-patch
             - name: br-ex
             - name: br-ex-physnet1-patch
        ovs-db:
           external_ids: {}
           other_config: { mac-table-size: 50000 }
        state: up
        type: ovs-bridge
        """
        expected_patch_port_cfg = """
        name: physnet0-br-ex-patch
        ipv4:
            dhcp: false
            enabled: false
        ipv6:
            autoconf: false
            dhcp: false
            enabled: false
        patch:
          peer: br-ex-physnet0-patch
        state: up
        type: ovs-interface
        """
        expected_patch_port_cfg_x = """
        name:  br-ex-physnet0-patch
        ipv4:
            dhcp: false
            enabled: false
        ipv6:
            autoconf: false
            dhcp: false
            enabled: false
        patch:
          peer: physnet0-br-ex-patch
        state: up
        type: ovs-interface
        """
        interface1 = objects.OvsPatchPort(
            'physnet0-br-ex-patch', peer='br-ex-physnet0-patch')
        interface2 = objects.OvsPatchPort(
            'br-ex-physnet0-patch', peer='physnet0-br-ex-patch')
        self.provider.add_ovs_patch_port(interface1)
        self.provider.add_ovs_patch_port(interface2)
        bridge = objects.OvsBridge('br-phys-0', use_dhcp=True,
                                   members=[interface1])
        bridge_ex = objects.OvsBridge('br-ex', use_dhcp=True,
                                      members=[interface2])
        self.provider.add_bridge(bridge)
        self.provider.add_bridge(bridge_ex)

        interface3 = objects.OvsPatchPort(
            'br-ex-physnet1-patch', peer='physnet1-br-ex-patch',
            bridge_name='br-ex')
        self.provider.add_ovs_patch_port(interface3)
        self.assertEqual(yaml.safe_load(expected_patch_port_cfg),
                         self.get_interface_config('physnet0-br-ex-patch'))
        self.assertEqual(yaml.safe_load(expected_patch_port_cfg_x),
                         self.get_interface_config('br-ex-physnet0-patch'))
        self.assertEqual(yaml.safe_load(expected_bridge_cfg),
                         self.get_bridge_config('br-phys-0'))
        self.assertEqual(yaml.safe_load(expected_bridge_ex_cfg),
                         self.get_bridge_config('br-ex'))

    def test_vlan_over_linux_bond(self):
        expected_vlan1_cfg = """
        name: vlan5
        type: vlan
        vlan:
            base-iface: bond0
            id: 5
        state: up
        ipv4:
            dhcp: false
            enabled: false
        ipv6:
            autoconf: false
            dhcp: false
            enabled: false
        """
        interface1 = objects.Interface('em1', primary=True)
        interface2 = objects.Interface('em2')
        bond = objects.LinuxBond('bond0', use_dhcp=True,
                                 members=[interface1, interface2])
        vlan = objects.Vlan('bond0', 5)
        self.provider.add_linux_bond(bond)
        self.provider.add_interface(interface1)
        self.provider.add_interface(interface2)
        self.provider.add_vlan(vlan)
        self.assertEqual(yaml.safe_load(expected_vlan1_cfg),
                         self.get_vlan_config('vlan5'))

    def test_add_vlan_route_rules(self):
        expected_vlan1_cfg = """
        name: vlan5
        type: vlan
        vlan:
            base-iface: em1
            id: 5
        state: up
        ipv4:
            dhcp: false
            enabled: true
            address:
                - ip: 192.168.1.2
                  prefix-length: 24
        ipv6:
            autoconf: false
            dhcp: false
            enabled: false
        """

        expected_route_table = """
            - destination: 172.19.0.0/24
              next-hop-address: 192.168.1.1
              next-hop-interface: vlan5
              table-id: 200
            - destination: 172.20.0.0/24
              next-hop-address: 192.168.1.1
              next-hop-interface: vlan5
              table-id: 201
            - destination: 172.21.0.0/24
              next-hop-address: 192.168.1.1
              next-hop-interface: vlan5
              table-id: 200
        """
        expected_rule = """
            - ip-from: 192.0.2.0/24
              route-table: 200
        """

        route_table1 = objects.RouteTable('table1', 200)
        self.provider.add_route_table(route_table1)

        route_rule1 = objects.RouteRule('from 192.0.2.0/24 table 200',
                                        'test comment')
        # Test route table by name
        route1 = objects.Route('192.168.1.1', '172.19.0.0/24', False,
                               route_table="table1")

        # Test that table specified in route_options takes precedence
        route2 = objects.Route('192.168.1.1', '172.20.0.0/24', False,
                               'table 201', route_table=200)
        # Test route table specified by integer ID
        route3 = objects.Route('192.168.1.1', '172.21.0.0/24', False,
                               route_table=200)
        v4_addr = objects.Address('192.168.1.2/24')
        vlan = objects.Vlan('em1', 5, addresses=[v4_addr],
                            routes=[route1, route2, route3],
                            rules=[route_rule1])
        self.provider.add_vlan(vlan)
        self.assertEqual(yaml.safe_load(expected_vlan1_cfg),
                         self.get_vlan_config('vlan5'))
        self.assertEqual(yaml.safe_load(expected_route_table),
                         self.get_route_config('vlan5'))
        self.assertEqual(yaml.safe_load(expected_rule),
                         self.get_rule_config())

    def test_sriov_pf_without_nicpart(self):
        nic_mapping = {'nic1': 'eth0', 'nic2': 'eth1', 'nic3': 'eth2'}
        self.stubbed_mapped_nics = nic_mapping

        pf = objects.SriovPF(name='nic3', numvfs=10)
        self.provider.add_sriov_pf(pf)
        exp_pf_config = """
        - name: eth2
          state: up
          type: ethernet
          ethernet:
            sr-iov:
              total-vfs: 10
              drivers-autoprobe: true
          ethtool:
            feature:
              hw-tc-offload: False
          ipv4:
            dhcp: False
            enabled: False
          ipv6:
            autoconf: False
            dhcp: False
            enabled: False
        """
        self.provider.apply_pf_config(False)
        self.assertEqual(yaml.safe_load(exp_pf_config),
                         list(self.provider.sriov_pf_data.values()))

    def test_sriov_pf_with_switchdev(self):
        nic_mapping = {'nic1': 'eth0', 'nic2': 'eth1', 'nic3': 'eth2'}
        self.stubbed_mapped_nics = nic_mapping

        def get_totalvfs_stub(iface_name):
            return 10
        self.stub_out('os_net_config.utils.get_totalvfs',
                      get_totalvfs_stub)

        pf = objects.SriovPF(name='nic3', numvfs=10, link_mode='switchdev')
        self.assertRaises(os_net_config.ConfigurationError,
                          self.provider.add_sriov_pf,
                          pf)

    def test_sriov_pf_with_vdpa(self):
        nic_mapping = {'nic1': 'eth0', 'nic2': 'eth1', 'nic3': 'eth2'}
        self.stubbed_mapped_nics = nic_mapping

        def get_totalvfs_stub(iface_name):
            return 10
        self.stub_out('os_net_config.utils.get_totalvfs',
                      get_totalvfs_stub)

        pf = objects.SriovPF(name='nic3', numvfs=10, vdpa=True)
        self.assertRaises(os_net_config.ConfigurationError,
                          self.provider.add_sriov_pf,
                          pf)

    def test_sriov_pf_without_capability(self):
        nic_mapping = {'nic1': 'eth0', 'nic2': 'eth1', 'nic3': 'eth2'}
        self.stubbed_mapped_nics = nic_mapping

        def get_totalvfs_stub(iface_name):
            return -1
        self.stub_out('os_net_config.utils.get_totalvfs',
                      get_totalvfs_stub)

        pf = objects.SriovPF(name='nic3', numvfs=10)
        self.assertRaises(os_net_config.ConfigurationError,
                          self.provider.add_sriov_pf,
                          pf)

    def test_sriov_pf_with_nicpart_ovs(self):
        nic_mapping = {'nic1': 'eth0', 'nic2': 'eth1', 'nic3': 'eth2'}
        self.stubbed_mapped_nics = nic_mapping

        self.stub_out("os_net_config.common.get_pci_address",
                      stub_get_pci_address)

        pf1 = objects.SriovPF(name='nic3', numvfs=10)
        self.provider.add_sriov_pf(pf1)
        pf2 = objects.SriovPF(name='nic2', numvfs=10)
        self.provider.add_sriov_pf(pf2)

        ovs_config = """
        type: ovs_bridge
        name: br-bond
        use_dhcp: true
        members:
        -
            type: ovs_bond
            name: bond_vf
            ovs_options: "bond_mode=active-backup"
            members:
            -
                type: sriov_vf
                device: nic3
                vfid: 2
                vlan_id: 112
                qos: 4
                primary: true
            -
                type: sriov_vf
                device: nic2
                vfid: 2
                vlan_id: 112
                qos: 4
        """

        ovs_obj = objects.object_from_json(yaml.safe_load(ovs_config))
        bond_vf = ovs_obj.members[0]
        for vf in bond_vf.members:
            self.provider.add_sriov_vf(vf)
        self.provider.add_bridge(ovs_obj)

        exp_pf_config = """
        - name: eth2
          state: up
          type: ethernet
          ethernet:
              sr-iov:
                  total-vfs: 10
                  drivers-autoprobe: true
                  vfs:
                  - id: 2
                    spoof-check: false
                    trust: true
                    vlan-id: 112
                    qos: 4
          ethtool:
             feature:
                hw-tc-offload: False
          ipv4:
              dhcp: False
              enabled: False
          ipv6:
              autoconf: False
              dhcp: False
              enabled: False
          dispatch:
              post-activation: |
                  dpdk_vfs=""
                  linux_vfs="2"
        - name: eth1
          state: up
          type: ethernet
          ethernet:
              sr-iov:
                  total-vfs: 10
                  drivers-autoprobe: true
                  vfs:
                  - id: 2
                    spoof-check: false
                    trust: true
                    vlan-id: 112
                    qos: 4
          ethtool:
             feature:
                hw-tc-offload: False
          ipv4:
              dhcp: False
              enabled: False
          ipv6:
              autoconf: False
              dhcp: False
              enabled: False
          dispatch:
              post-activation: |
                  dpdk_vfs=""
                  linux_vfs="2"
        """

        exp_bridge_config = """
        name: br-bond
        state: up
        type: ovs-bridge
        bridge:
            allow-extra-patch-ports: True
            options:
                fail-mode: standalone
                mcast-snooping-enable: False
                rstp: False
                stp: False
            port:
                - name: bond_vf
                  link-aggregation:
                      mode: active-backup
                      ovs-db:
                          other_config:
                              bond-primary: eth2_2
                      port:
                          - name: eth2_2
                          - name: eth1_2
                - name: br-bond
        ovs-db:
            external_ids: {}
            other_config: { mac-table-size: 50000 }
        """

        self.provider.apply_vf_config(False)
        self.assertEqual(yaml.safe_load(exp_pf_config),
                         list(self.provider.sriov_pf_data.values()))
        self.assertEqual(yaml.safe_load(exp_bridge_config),
                         self.get_bridge_config('br-bond'))

    def test_sriov_pf_with_nicpart_ovs_user_bridge_no_bond(self):
        nic_mapping = {'nic1': 'eth0', 'nic2': 'eth1', 'nic3': 'eth2'}
        self.stubbed_mapped_nics = nic_mapping

        self.stub_out('os_net_config.common.get_pci_address',
                      stub_get_pci_address)

        pf2 = objects.SriovPF(name='nic2', numvfs=10)
        self.provider.add_sriov_pf(pf2)

        ovs_config = """
        type: ovs_user_bridge
        name: br-dpdk2
        members:
          -
            type: ovs_dpdk_port
            name: dpdk2
            members:
              -
                type: sriov_vf
                device: nic2
                vfid: 2
                vlan_id: 112
                qos: 4
        """

        ovs_obj = objects.object_from_json(yaml.safe_load(ovs_config))
        self.provider.add_sriov_vf(ovs_obj.members[0].members[0])
        self.provider.add_ovs_dpdk_port(ovs_obj.members[0])
        self.provider.add_ovs_user_bridge(ovs_obj)

        exp_pf_config = """
        - name: eth1
          state: up
          type: ethernet
          ethernet:
              sr-iov:
                  total-vfs: 10
                  drivers-autoprobe: true
                  vfs:
                  - id: 2
                    spoof-check: false
                    trust: true
                    vlan-id: 112
                    qos: 4
          ethtool:
             feature:
                hw-tc-offload: False
          ipv4:
              dhcp: False
              enabled: False
          ipv6:
              autoconf: False
              dhcp: False
              enabled: False
          dispatch:
              post-activation: |
                  dpdk_vfs="2"
                  linux_vfs=""
        """

        exp_bridge_config = """
        name: br-dpdk2
        state: up
        type: ovs-bridge
        bridge:
            allow-extra-patch-ports: True
            options:
                datapath: netdev
                fail-mode: standalone
                mcast-snooping-enable: False
                rstp: False
                stp: False
            port:
                - name: dpdk2
                - name: br-dpdk2
        ovs-db:
            external_ids: {}
            other_config: {'mac-table-size': 50000}
        """

        self.provider.apply_vf_config(False)
        self.assertEqual(yaml.safe_load(exp_pf_config),
                         list(self.provider.sriov_pf_data.values()))
        self.assertEqual(yaml.safe_load(exp_bridge_config),
                         self.get_bridge_config('br-dpdk2'))

    def test_dpdkbond_regular(self):
        common.set_noop(False)
        nic_mapping = {'nic1': 'eth0', 'nic2': 'eth1', 'nic3': 'eth2'}
        self.stubbed_mapped_nics = nic_mapping

        self.stub_out('os_net_config.common.get_dpdk_pci_address',
                      stub_get_dpdk_pci_address)
        ovs_config = """
        type: ovs_user_bridge
        name: br-bond
        members:
          -
            type: ovs_dpdk_bond
            name: dpdkbond1
            ovs_options: "bond_mode=active-backup"
            members:
              -
                type: ovs_dpdk_port
                name: dpdk2
                members:
                  -
                    type: interface
                    name: nic2
              -
                type: ovs_dpdk_port
                name: dpdk3
                members:
                  -
                    type: interface
                    name: nic3
        """

        def test_bind_dpdk_interfaces(ifname, driver, noop):
            return
        self.stub_out('os_net_config.utils.bind_dpdk_interfaces',
                      test_bind_dpdk_interfaces)

        ovs_obj = objects.object_from_json(yaml.safe_load(ovs_config))
        dpdk_bond = ovs_obj.members[0]
        self.provider.add_ovs_user_bridge(ovs_obj)
        self.provider.add_ovs_dpdk_bond(dpdk_bond)

        exp_bridge_config = """
        name: br-bond
        state: up
        type: ovs-bridge
        bridge:
            allow-extra-patch-ports: True
            options:
                datapath: netdev
                fail-mode: standalone
                mcast-snooping-enable: False
                rstp: False
                stp: False
            port:
                - name: dpdkbond1
                  link-aggregation:
                      mode: active-backup
                      ovs-db:
                          other_config:
                              bond-primary: dpdk2
                      port:
                          - name: dpdk2
                          - name: dpdk3
                - name: br-bond
        ovs-db:
            external_ids: {}
            other_config: {'mac-table-size': 50000}
        """

        exp_dpdk2_config = """
        dpdk:
          devargs: "0000:07:00.1"
        ipv4:
          dhcp: False
          enabled: False
        ipv6:
          autoconf: False
          dhcp: False
          enabled: False
        name: dpdk2
        ovs-db:
          external_ids: {}
          other_config: {}
        state: up
        type: ovs-interface
        """

        exp_dpdk3_config = """
        dpdk:
          devargs: "0000:08:00.1"
        ipv4:
          dhcp: False
          enabled: False
        ipv6:
          autoconf: False
          dhcp: False
          enabled: False
        name: dpdk3
        ovs-db:
          external_ids: {}
          other_config: {}
        state: up
        type: ovs-interface
        """

        self.assertEqual(yaml.safe_load(exp_dpdk2_config),
                         self.get_interface_config('dpdk2'))
        self.assertEqual(yaml.safe_load(exp_dpdk3_config),
                         self.get_interface_config('dpdk3'))
        self.assertEqual(yaml.safe_load(exp_bridge_config),
                         self.get_bridge_config('br-bond'))

    def test_dpdkbond_custom(self):
        common.set_noop(False)
        nic_mapping = {'nic1': 'eth0', 'nic2': 'eth1', 'nic3': 'eth2'}
        self.stubbed_mapped_nics = nic_mapping

        self.stub_out('os_net_config.common.get_dpdk_pci_address',
                      stub_get_dpdk_pci_address)
        ovs_config = """
        type: ovs_user_bridge
        name: br-bond
        members:
          -
            type: ovs_dpdk_bond
            name: dpdkbond1
            ovs_options: "bond_mode=balance-slb"
            rx_queue: 2
            rx_queue_size: 2048
            tx_queue_size: 2048
            mtu: 9000
            members:
              -
                type: ovs_dpdk_port
                name: dpdk2
                members:
                  -
                    type: interface
                    name: nic2
              -
                type: ovs_dpdk_port
                name: dpdk3
                members:
                  -
                    type: interface
                    name: nic3
        """

        def test_bind_dpdk_interfaces(ifname, driver, noop):
            return
        self.stub_out('os_net_config.utils.bind_dpdk_interfaces',
                      test_bind_dpdk_interfaces)

        ovs_obj = objects.object_from_json(yaml.safe_load(ovs_config))
        dpdk_bond = ovs_obj.members[0]
        self.provider.add_ovs_user_bridge(ovs_obj)
        self.provider.add_ovs_dpdk_bond(dpdk_bond)

        exp_bridge_config = """
        name: br-bond
        state: up
        type: ovs-bridge
        bridge:
            allow-extra-patch-ports: True
            options:
                datapath: netdev
                fail-mode: standalone
                mcast-snooping-enable: False
                rstp: False
                stp: False
            port:
                - name: dpdkbond1
                  link-aggregation:
                      mode: balance-slb
                      ovs-db:
                          other_config:
                              bond-primary: dpdk2
                      port:
                          - name: dpdk2
                          - name: dpdk3
                - name: br-bond
        ovs-db:
            external_ids: {}
            other_config: {'mac-table-size': 50000}
        """

        exp_dpdk2_config = """
        dpdk:
          devargs: "0000:07:00.1"
          n_rxq_desc: 2048
          n_txq_desc: 2048
          rx-queue: 2
        ipv4:
          dhcp: False
          enabled: False
        ipv6:
          autoconf: False
          dhcp: False
          enabled: False
        mtu: 9000
        name: dpdk2
        ovs-db:
          external_ids: {}
          other_config: {}
        state: up
        type: ovs-interface
        """

        exp_dpdk3_config = """
        dpdk:
          devargs: "0000:08:00.1"
          n_rxq_desc: 2048
          n_txq_desc: 2048
          rx-queue: 2
        ipv4:
          dhcp: False
          enabled: False
        ipv6:
          autoconf: False
          dhcp: False
          enabled: False
        mtu: 9000
        name: dpdk3
        ovs-db:
          external_ids: {}
          other_config: {}
        state: up
        type: ovs-interface
        """

        self.assertEqual(yaml.safe_load(exp_dpdk2_config),
                         self.get_interface_config('dpdk2'))
        self.assertEqual(yaml.safe_load(exp_dpdk3_config),
                         self.get_interface_config('dpdk3'))
        self.assertEqual(yaml.safe_load(exp_bridge_config),
                         self.get_bridge_config('br-bond'))

    def test_dpdkbond_ovs_extra(self):
        common.set_noop(False)
        nic_mapping = {'nic1': 'eth0', 'nic2': 'eth1', 'nic3': 'eth2'}
        self.stubbed_mapped_nics = nic_mapping

        ovs_config = """
        type: ovs_user_bridge
        name: br-bond
        members:
          -
            type: ovs_dpdk_bond
            name: dpdkbond1
            mtu: 9000
            rx_queue: 1
            ovs_extra:
              - set port dpdkbond1 bond_mode=balance-slb
              - set port dpdkbond1 bond_updelay=1000
              - set port dpdkbond1 other_config:bond-detect-mode=miimon
              - set port dpdkbond1 other_config:bond-miimon-interval=100
              - set Interface dpdk2 options:n_rxq_desc=2048
              - set Interface dpdk2 options:n_txq_desc=2048
              - set Interface dpdk3 options:n_rxq_desc=2048
              - set Interface dpdk3 options:n_txq_desc=2048
            mtu: 9000
            members:
              -
                type: ovs_dpdk_port
                name: dpdk2
                members:
                  -
                    type: interface
                    name: nic2
              -
                type: ovs_dpdk_port
                name: dpdk3
                members:
                  -
                    type: interface
                    name: nic3
        """

        def test_bind_dpdk_interfaces(ifname, driver, noop):
            return
        self.stub_out('os_net_config.utils.bind_dpdk_interfaces',
                      test_bind_dpdk_interfaces)
        self.stub_out('os_net_config.common.get_dpdk_pci_address',
                      stub_get_dpdk_pci_address)

        ovs_obj = objects.object_from_json(yaml.safe_load(ovs_config))
        self.provider.add_ovs_user_bridge(ovs_obj)
        dpdk_bond = ovs_obj.members[0]
        self.provider.add_ovs_dpdk_bond(dpdk_bond)

        exp_bridge_config = """
        name: br-bond
        state: up
        type: ovs-bridge
        bridge:
            allow-extra-patch-ports: True
            options:
                datapath: netdev
                fail-mode: standalone
                mcast-snooping-enable: False
                rstp: False
                stp: False
            port:
                - name: dpdkbond1
                  link-aggregation:
                      mode: balance-slb
                      bond-updelay: 1000
                      ovs-db:
                          other_config:
                              bond-primary: dpdk2
                              bond-detect-mode: miimon
                              bond-miimon-interval: 100
                      port:
                          - name: dpdk2
                          - name: dpdk3
                - name: br-bond
        ovs-db:
            external_ids: {}
            other_config: {'mac-table-size': 50000}
        """

        exp_dpdk2_config = """
        dpdk:
          devargs: "0000:07:00.1"
          n_rxq_desc: 2048
          n_txq_desc: 2048
          rx-queue: 1
        ipv4:
          dhcp: False
          enabled: False
        ipv6:
          autoconf: False
          dhcp: False
          enabled: False
        mtu: 9000
        name: dpdk2
        ovs-db:
          external_ids: {}
          other_config: {}
        state: up
        type: ovs-interface
        """

        exp_dpdk3_config = """
        dpdk:
          devargs: "0000:08:00.1"
          n_rxq_desc: 2048
          n_txq_desc: 2048
          rx-queue: 1
        ipv4:
          dhcp: False
          enabled: False
        ipv6:
          autoconf: False
          dhcp: False
          enabled: False
        mtu: 9000
        name: dpdk3
        ovs-db:
          external_ids: {}
          other_config: {}
        state: up
        type: ovs-interface
        """

        self.assertEqual(yaml.safe_load(exp_dpdk2_config),
                         self.get_interface_config('dpdk2'))
        self.assertEqual(yaml.safe_load(exp_dpdk3_config),
                         self.get_interface_config('dpdk3'))
        self.assertEqual(yaml.safe_load(exp_bridge_config),
                         self.get_bridge_config('br-bond'))

    def test_dpdkbond_ovs_extra_grouped(self):
        common.set_noop(False)
        nic_mapping = {'nic1': 'eth0', 'nic2': 'eth1', 'nic3': 'eth2'}
        self.stubbed_mapped_nics = nic_mapping

        self.stub_out('os_net_config.common.get_dpdk_pci_address',
                      stub_get_dpdk_pci_address)

        ovs_config = """
        type: ovs_user_bridge
        name: br-bond
        members:
          -
            type: ovs_dpdk_bond
            name: dpdkbond1
            mtu: 9000
            rx_queue: 1
            ovs_extra:
              - set port dpdkbond1 bond_mode=balance-slb bond_updelay=1000
              - set port dpdkbond1 other_config:bond-detect-mode=miimon \
                      other_config:bond-miimon-interval=100
              - set Interface dpdk2 options:n_rxq_desc=2048 \
                      options:n_txq_desc=2048
              - set Interface dpdk3 options:n_rxq_desc=2048 \
                      options:n_txq_desc=2048
            mtu: 9000
            members:
              -
                type: ovs_dpdk_port
                name: dpdk2
                members:
                  -
                    type: interface
                    name: nic2
              -
                type: ovs_dpdk_port
                name: dpdk3
                members:
                  -
                    type: interface
                    name: nic3
        """

        def test_bind_dpdk_interfaces(ifname, driver, noop):
            return
        self.stub_out('os_net_config.utils.bind_dpdk_interfaces',
                      test_bind_dpdk_interfaces)

        ovs_obj = objects.object_from_json(yaml.safe_load(ovs_config))
        self.provider.add_ovs_user_bridge(ovs_obj)
        dpdk_bond = ovs_obj.members[0]
        self.provider.add_ovs_dpdk_bond(dpdk_bond)

        exp_bridge_config = """
        name: br-bond
        state: up
        type: ovs-bridge
        bridge:
            allow-extra-patch-ports: True
            options:
                datapath: netdev
                fail-mode: standalone
                mcast-snooping-enable: False
                rstp: False
                stp: False
            port:
                - name: dpdkbond1
                  link-aggregation:
                      mode: balance-slb
                      bond-updelay: 1000
                      ovs-db:
                          other_config:
                              bond-primary: dpdk2
                              bond-detect-mode: miimon
                              bond-miimon-interval: 100
                      port:
                          - name: dpdk2
                          - name: dpdk3
                - name: br-bond
        ovs-db:
            external_ids: {}
            other_config: {'mac-table-size': 50000}
        """

        exp_dpdk2_config = """
        dpdk:
          devargs: "0000:07:00.1"
          n_rxq_desc: 2048
          n_txq_desc: 2048
          rx-queue: 1
        ipv4:
          dhcp: False
          enabled: False
        ipv6:
          autoconf: False
          dhcp: False
          enabled: False
        mtu: 9000
        name: dpdk2
        ovs-db:
          external_ids: {}
          other_config: {}
        state: up
        type: ovs-interface
        """

        exp_dpdk3_config = """
        dpdk:
          devargs: "0000:08:00.1"
          n_rxq_desc: 2048
          n_txq_desc: 2048
          rx-queue: 1
        ipv4:
          dhcp: False
          enabled: False
        ipv6:
          autoconf: False
          dhcp: False
          enabled: False
        mtu: 9000
        name: dpdk3
        ovs-db:
          external_ids: {}
          other_config: {}
        state: up
        type: ovs-interface
        """

        self.assertEqual(yaml.safe_load(exp_dpdk2_config),
                         self.get_interface_config('dpdk2'))
        self.assertEqual(yaml.safe_load(exp_dpdk3_config),
                         self.get_interface_config('dpdk3'))
        self.assertEqual(yaml.safe_load(exp_bridge_config),
                         self.get_bridge_config('br-bond'))

    def test_sriov_pf_with_nicpart_ovs_user_bridge(self):
        nic_mapping = {'nic1': 'eth0', 'nic2': 'eth1', 'nic3': 'eth2'}
        self.stubbed_mapped_nics = nic_mapping

        self.stub_out("os_net_config.common.get_pci_address",
                      stub_get_pci_address)

        pf1 = objects.SriovPF(name='nic3', numvfs=10)
        self.provider.add_sriov_pf(pf1)
        pf2 = objects.SriovPF(name='nic2', numvfs=10)
        self.provider.add_sriov_pf(pf2)

        ovs_config = """
        type: ovs_user_bridge
        name: br-bond
        members:
          -
            type: ovs_dpdk_bond
            name: dpdkbond1
            ovs_options: "bond_mode=active-backup"
            members:
              -
                type: ovs_dpdk_port
                name: dpdk2
                members:
                  -
                    type: sriov_vf
                    device: nic2
                    vfid: 2
                    vlan_id: 112
                    qos: 4
                    primary: true
              -
                type: ovs_dpdk_port
                name: dpdk3
                members:
                  -
                    type: sriov_vf
                    device: nic3
                    vfid: 2
                    vlan_id: 112
                    qos: 4
        """

        ovs_obj = objects.object_from_json(yaml.safe_load(ovs_config))
        dpdk_bond = ovs_obj.members[0]
        for dpdk_port in dpdk_bond.members:
            vf = dpdk_port.members[0]
            self.provider.add_sriov_vf(vf)
            self.provider.add_ovs_dpdk_port(dpdk_port)
        self.provider.add_ovs_user_bridge(ovs_obj)

        exp_pf_config = """
        - name: eth2
          state: up
          type: ethernet
          ethernet:
              sr-iov:
                  total-vfs: 10
                  drivers-autoprobe: true
                  vfs:
                  - id: 2
                    spoof-check: false
                    trust: true
                    vlan-id: 112
                    qos: 4
          ethtool:
             feature:
                hw-tc-offload: False
          ipv4:
              dhcp: False
              enabled: False
          ipv6:
              autoconf: False
              dhcp: False
              enabled: False
          dispatch:
              post-activation: |
                  dpdk_vfs="2"
                  linux_vfs=""
        - name: eth1
          state: up
          type: ethernet
          ethernet:
              sr-iov:
                  total-vfs: 10
                  drivers-autoprobe: true
                  vfs:
                  - id: 2
                    spoof-check: false
                    trust: true
                    vlan-id: 112
                    qos: 4
          ethtool:
             feature:
                hw-tc-offload: False
          ipv4:
              dhcp: False
              enabled: False
          ipv6:
              autoconf: False
              dhcp: False
              enabled: False
          dispatch:
              post-activation: |
                  dpdk_vfs="2"
                  linux_vfs=""
        """

        exp_bridge_config = """
        name: br-bond
        state: up
        type: ovs-bridge
        bridge:
            allow-extra-patch-ports: True
            options:
                datapath: netdev
                fail-mode: standalone
                mcast-snooping-enable: False
                rstp: False
                stp: False
            port:
                - name: dpdkbond1
                  link-aggregation:
                      mode: active-backup
                      ovs-db:
                          other_config:
                              bond-primary: dpdk2
                      port:
                          - name: dpdk2
                          - name: dpdk3
                - name: br-bond
        ovs-db:
            external_ids: {}
            other_config: {'mac-table-size': 50000}
        """

        self.provider.apply_vf_config(False)
        self.assertEqual(yaml.safe_load(exp_pf_config),
                         list(self.provider.sriov_pf_data.values()))
        self.assertEqual(yaml.safe_load(exp_bridge_config),
                         self.get_bridge_config('br-bond'))

    def test_sriov_pf_with_custom_nicpart_ovs_user_bridge(self):
        nic_mapping = {'nic1': 'eth0', 'nic2': 'eth1', 'nic3': 'eth2'}
        self.stubbed_mapped_nics = nic_mapping

        self.stub_out("os_net_config.common.get_pci_address",
                      stub_get_pci_address)

        pf1 = objects.SriovPF(name='nic3', numvfs=10)
        self.provider.add_sriov_pf(pf1)
        pf2 = objects.SriovPF(name='nic2', numvfs=10)
        self.provider.add_sriov_pf(pf2)

        ovs_config = """
        type: ovs_user_bridge
        name: br-bond
        members:
          -
            type: ovs_dpdk_bond
            name: dpdkbond1
            ovs_options: "bond_mode=active-backup"
            members:
              -
                type: ovs_dpdk_port
                name: dpdk2
                members:
                  -
                    type: sriov_vf
                    device: nic2
                    vfid: 2
                    vlan_id: 112
                    qos: 4
                    trust: off
                    spoofcheck: on
                    primary: true
              -
                type: ovs_dpdk_port
                name: dpdk3
                members:
                  -
                    type: sriov_vf
                    device: nic3
                    vfid: 2
                    vlan_id: 112
                    qos: 4
                    trust: off
                    spoofcheck: on
        """

        ovs_obj = objects.object_from_json(yaml.safe_load(ovs_config))
        dpdk_bond = ovs_obj.members[0]
        for dpdk_port in dpdk_bond.members:
            vf = dpdk_port.members[0]
            self.provider.add_sriov_vf(vf)
            self.provider.add_ovs_dpdk_port(dpdk_port)
        self.provider.add_ovs_user_bridge(ovs_obj)

        exp_pf_config = """
        - name: eth2
          state: up
          type: ethernet
          ethernet:
              sr-iov:
                  total-vfs: 10
                  drivers-autoprobe: true
                  vfs:
                  - id: 2
                    spoof-check: true
                    trust: false
                    vlan-id: 112
                    qos: 4
          ethtool:
             feature:
                hw-tc-offload: False
          ipv4:
              dhcp: False
              enabled: False
          ipv6:
              autoconf: False
              dhcp: False
              enabled: False
          dispatch:
              post-activation: |
                  dpdk_vfs="2"
                  linux_vfs=""
        - name: eth1
          state: up
          type: ethernet
          ethernet:
              sr-iov:
                  total-vfs: 10
                  drivers-autoprobe: true
                  vfs:
                  - id: 2
                    spoof-check: true
                    trust: false
                    vlan-id: 112
                    qos: 4
          ethtool:
             feature:
                hw-tc-offload: False
          ipv4:
              dhcp: False
              enabled: False
          ipv6:
              autoconf: False
              dhcp: False
              enabled: False
          dispatch:
              post-activation: |
                  dpdk_vfs="2"
                  linux_vfs=""
        """

        exp_bridge_config = """
        name: br-bond
        state: up
        type: ovs-bridge
        bridge:
            allow-extra-patch-ports: True
            options:
                datapath: netdev
                fail-mode: standalone
                mcast-snooping-enable: False
                rstp: False
                stp: False
            port:
                - name: dpdkbond1
                  link-aggregation:
                      mode: active-backup
                      ovs-db:
                          other_config:
                              bond-primary: dpdk2
                      port:
                          - name: dpdk2
                          - name: dpdk3
                - name: br-bond
        ovs-db:
            external_ids: {}
            other_config: {'mac-table-size': 50000}
        """

        self.provider.apply_vf_config(False)
        self.assertEqual(yaml.safe_load(exp_pf_config),
                         list(self.provider.sriov_pf_data.values()))
        self.assertEqual(yaml.safe_load(exp_bridge_config),
                         self.get_bridge_config('br-bond'))

    def test_sriov_pf_with_nicpart_linux_bond(self):
        nic_mapping = {'nic1': 'eth0', 'nic2': 'eth1', 'nic3': 'eth2'}
        self.stubbed_mapped_nics = nic_mapping
        self.stub_out("os_net_config.common.get_pci_address",
                      stub_get_pci_address)

        pf1 = objects.SriovPF(name='nic3', numvfs=10)
        self.provider.add_sriov_pf(pf1)
        pf2 = objects.SriovPF(name='nic2', numvfs=10)
        self.provider.add_sriov_pf(pf2)

        lnxbond_config = """
        type: linux_bond
        name: bond_lnx
        use_dhcp: true
        bonding_options: "mode=active-backup"
        members:
        -
          type: sriov_vf
          device: eth1
          vfid: 3
          vlan_id: 113
          qos: 5
          primary: true
        -
          type: sriov_vf
          device: eth2
          vfid: 3
          vlan_id: 113
          qos: 5
        """

        lb_obj = objects.object_from_json(yaml.safe_load(lnxbond_config))
        for vf_obj in lb_obj.members:
            self.provider.add_sriov_vf(vf_obj)
        self.provider.add_linux_bond(lb_obj)

        exp_pf_config = """
        - name: eth2
          state: up
          type: ethernet
          ethernet:
              sr-iov:
                  total-vfs: 10
                  drivers-autoprobe: true
                  vfs:
                  - id: 3
                    spoof-check: false
                    trust: true
                    vlan-id: 113
                    qos: 5
          ethtool:
             feature:
                hw-tc-offload: False
          ipv4:
              dhcp: False
              enabled: False
          ipv6:
              autoconf: False
              dhcp: False
              enabled: False
          dispatch:
              post-activation: |
                  dpdk_vfs=""
                  linux_vfs="3"
        - name: eth1
          state: up
          type: ethernet
          ethernet:
              sr-iov:
                  total-vfs: 10
                  drivers-autoprobe: true
                  vfs:
                  - id: 3
                    spoof-check: false
                    trust: true
                    vlan-id: 113
                    qos: 5
          ethtool:
             feature:
                hw-tc-offload: False
          ipv4:
              dhcp: False
              enabled: False
          ipv6:
              autoconf: False
              dhcp: False
              enabled: False
          dispatch:
              post-activation: |
                  dpdk_vfs=""
                  linux_vfs="3"
        """

        exp_bond_config = """
        name: bond_lnx
        state: up
        type: bond
        ipv4:
            auto-dns: true
            auto-gateway: true
            auto-routes: true
            dhcp: true
            enabled: true
        ipv6:
            autoconf: false
            dhcp: false
            enabled: false
        link-aggregation:
            mode: active-backup
            options:
                primary: eth1_3
            port:
                - eth1_3
                - eth2_3
        """

        self.provider.apply_vf_config(False)
        self.assertEqual(yaml.safe_load(exp_pf_config),
                         list(self.provider.sriov_pf_data.values()))
        self.assertEqual(yaml.safe_load(exp_bond_config),
                         self.get_linuxbond_config('bond_lnx'))

    def test_infiniband_parent(self):
        expected_ib_config = """
        ipv4:
            dhcp: False
            enabled: False
        ipv6:
            autoconf: False
            dhcp: False
            enabled: False
        mtu: 1400
        name: ib0
        state: up
        type: infiniband
        infiniband:
            mode: datagram
        """

        interface1 = objects.Interface('ib0', mtu=1400)
        self.provider.add_ib_interface(interface1)
        self.assertEqual(yaml.safe_load(expected_ib_config),
                         self.get_interface_config('ib0'))

        expected_ib2_config = """
        name: ib0.8064
        ipv4:
            dhcp: False
            enabled: True
            address:
                - ip: 192.168.1.2
                  prefix-length: 24
        ipv6:
            autoconf: False
            dhcp: False
            enabled: False
        state: up
        type: infiniband
        infiniband:
            pkey: "0x8064"
            base-iface: ib0
            mode: datagram
        """
        v4_addr = objects.Address('192.168.1.2/24')
        interface2 = objects.IbChildInterface(parent='ib0',
                                              pkey_id=100,
                                              addresses=[v4_addr])
        self.provider.add_ib_child_interface(interface2)
        self.assertEqual(yaml.safe_load(expected_ib2_config),
                         self.get_interface_config('ib0.8064'))

    def test_ovs_interface_with_valid_external_ids(self):
        """Test OVS interface with valid external-ids commands"""
        expected_config = """
        name: eno2
        type: ethernet
        state: up
        ovs-db:
            external_ids:
                vm-uuid: 12345
                system-id: compute-1
        ethernet:
            sr-iov:
                total-vfs: 0
        ipv4:
            enabled: false
            dhcp: false
        ipv6:
            enabled: false
            dhcp: false
            autoconf: false
        """

        # Valid external-ids commands with both formats
        ovs_extra = [
            "set interface {name} external-ids:vm-uuid=12345",
            "set interface eno2 external_ids:system-id=compute-1"
        ]
        interface = objects.Interface('eno2', ovs_extra=ovs_extra)
        interface.ovs_port = True
        self.provider.add_interface(interface)
        self.assertEqual(yaml.safe_load(expected_config),
                         self.get_interface_config('eno2'))

    def test_ovs_interface_with_valid_mixed_commands(self):
        """Test OVS interface with valid mixed external-ids commands"""
        expected_config = """
        name: eth1
        type: ethernet
        state: up
        ovs-db:
            external_ids:
                environment: production
                role: compute
                tenant: main
        ethernet:
            sr-iov:
                total-vfs: 0
        ipv4:
            enabled: false
            dhcp: false
        ipv6:
            enabled: false
            dhcp: false
            autoconf: false
        """

        # Mix of hardcoded and template-based commands
        ovs_extra = [
            "set interface {name} external-ids:environment=production",
            "set interface eth1 external_ids:role=compute",
            "set interface {name} external-ids:tenant=main"
        ]
        interface = objects.Interface('eth1', ovs_extra=ovs_extra)
        interface.ovs_port = True
        self.provider.add_interface(interface)
        self.assertEqual(yaml.safe_load(expected_config),
                         self.get_interface_config('eth1'))

    def test_ovs_interface_invalid_external_ids_format(self):
        """Test OVS interface with invalid external-ids format raises error"""
        # Malformed external-ids command (missing '=' sign)
        ovs_extra = ["set interface {name} external-ids:vm-uuid"]
        interface = objects.Interface('eno2', ovs_extra=ovs_extra)
        interface.ovs_port = True

        self.assertRaises(os_net_config.ConfigurationError,
                          self.provider.add_interface,
                          interface)

    def test_ovs_interface_interface_name_mismatch(self):
        """Test OVS interface with interface name mismatch raises error"""
        # Interface name in command doesn't match actual interface name
        ovs_extra = ["set interface eth1 external-ids:vm-uuid=12345"]
        interface = objects.Interface('eno2', ovs_extra=ovs_extra)
        interface.ovs_port = True

        self.assertRaises(os_net_config.ConfigurationError,
                          self.provider.add_interface,
                          interface)

    def test_ovs_interface_unsupported_command_type(self):
        """Test OVS interface with unsupported command type raises error"""
        # Commands other than external-ids are not supported for interfaces
        ovs_extra = ["set interface {name} other_config:datapath-id=12345"]
        interface = objects.Interface('eno2', ovs_extra=ovs_extra)
        interface.ovs_port = True

        self.assertRaises(os_net_config.ConfigurationError,
                          self.provider.add_interface,
                          interface)

    def test_ovs_interface_invalid_command_syntax(self):
        """Test OVS interface with invalid command syntax raises error"""
        # Malformed command syntax (typo in 'external-ids')
        ovs_extra = ["set interface {name} junkids:vm-uuid=12345"]
        interface = objects.Interface('eno2', ovs_extra=ovs_extra)
        interface.ovs_port = True

        self.assertRaises(os_net_config.ConfigurationError,
                          self.provider.add_interface,
                          interface)

    def test_ovs_interface_multiple_errors(self):
        """Test OVS interface with multiple invalid commands raises error"""
        # Multiple invalid commands
        ovs_extra = [
            "set interface {name} external-ids:valid=12345",     # Valid
            "set interface {name} other_config:invalid=test",    # Invalid
            "set interface eth1 external-ids:mismatch=test"      # Wrong name
        ]
        interface = objects.Interface('eno2', ovs_extra=ovs_extra)
        interface.ovs_port = True

        self.assertRaises(os_net_config.ConfigurationError,
                          self.provider.add_interface,
                          interface)

    def test_ovs_interface_empty_ovs_extra(self):
        """Test OVS interface with empty ovs_extra succeeds"""
        expected_config = """
        name: eno2
        type: ethernet
        state: up
        ethernet:
            sr-iov:
                total-vfs: 0
        ipv4:
            enabled: false
            dhcp: false
        ipv6:
            enabled: false
            dhcp: false
            autoconf: false
        """

        # Empty ovs_extra should work fine
        interface = objects.Interface('eno2', ovs_extra=[])
        interface.ovs_port = True
        self.provider.add_interface(interface)
        self.assertEqual(yaml.safe_load(expected_config),
                         self.get_interface_config('eno2'))

    def test_sriov_vf_with_valid_ovs_extra(self):
        """Test SR-IOV VF interface with valid external-ids commands"""
        # Standard mapping
        nic_mapping = {'nic1': 'eth0', 'nic2': 'eth1', 'nic3': 'eth2'}
        self.stubbed_mapped_nics = nic_mapping

        # Add required stubs for SR-IOV functionality
        self.stub_out("os_net_config.common.get_pci_address",
                      stub_get_pci_address)

        # First add the Physical Function (PF) - this is required!
        pf = objects.SriovPF(name='nic2', numvfs=10)
        self.provider.add_sriov_pf(pf)

        # Define OVS config with SR-IOV VF (following the working pattern)
        ovs_config = """
        type: ovs_bridge
        name: br-test
        members:
          -
            type: sriov_vf
            device: nic2
            vfid: 2
            ovs_extra:
              - "set interface {name} external-ids:vm-id=vm-12345"
              - "set interface {name} external_ids:vlan=production"
        """

        def test_get_vf_devname(device, vfid):
            return device + '_' + str(vfid)

        self.stub_out('os_net_config.utils.get_vf_devname',
                      test_get_vf_devname)

        # Parse and add SR-IOV VF using the working pattern
        ovs_obj = objects.object_from_json(yaml.safe_load(ovs_config))
        # Extract VF directly from bridge (simplified structure)
        vf = ovs_obj.members[0]
        self.provider.add_sriov_vf(vf)

        # Validation passes if no ConfigurationError is raised
        # The OVS extra validation should allow these valid commands

    def test_sriov_vf_with_invalid_ovs_extra(self):
        """Test SR-IOV VF interface with invalid external-ids commands"""
        # Standard mapping
        nic_mapping = {'nic1': 'eth0', 'nic2': 'eth1', 'nic3': 'eth2'}
        self.stubbed_mapped_nics = nic_mapping

        # Add required stubs for SR-IOV functionality
        self.stub_out("os_net_config.common.get_pci_address",
                      stub_get_pci_address)

        # First add the Physical Function (PF) - this is required!
        pf = objects.SriovPF(name='nic2', numvfs=10)
        self.provider.add_sriov_pf(pf)
        # Define OVS config with invalid external-ids command
        ovs_config = """
        type: ovs_bridge
        name: br-test
        members:
          -
            type: sriov_vf
            device: nic2
            vfid: 2
            ovs_extra:
              - "set interface {name} external-ids:invalid-syntax"
        """

        def test_get_vf_devname(device, vfid):
            return device + '_' + str(vfid)

        self.stub_out('os_net_config.utils.get_vf_devname',
                      test_get_vf_devname)

        # Parse and try to add SR-IOV VF with invalid ovs_extra
        ovs_obj = objects.object_from_json(yaml.safe_load(ovs_config))
        # Extract VF directly from bridge (simplified structure)
        vf = ovs_obj.members[0]

        self.assertRaises(os_net_config.ConfigurationError,
                          self.provider.add_sriov_vf,
                          vf)

    def test_get_handled_ovs_extra_function(self):
        """Test the new get_handled_ovs_extra helper function"""
        nic_mapping = {'nic1': 'eth0', 'nic2': 'eth1'}
        self.stubbed_mapped_nics = nic_mapping

        original_list = [
            "set bridge {name} fail_mode=standalone",
            "set bridge {name} other_config:mac-table-size=50000",
            "set interface {name} external_ids:vm-id=12345",
            "invalid command that fails"
        ]

        unhandled_list = [
            "invalid command that fails"
        ]

        # Test the difference calculation
        handled_commands = self.provider.get_handled_ovs_extra(
            original_list, unhandled_list)

        expected_handled = [
            "set bridge {name} fail_mode=standalone",
            "set bridge {name} other_config:mac-table-size=50000",
            "set interface {name} external_ids:vm-id=12345"
        ]

        self.assertEqual(expected_handled, handled_commands)

    def test_bridge_sequential_parsing_chain(self):
        """Test the new sequential parsing chain: iface->ports->bridge"""
        nic_mapping = {'nic1': 'eth0', 'nic2': 'eth1'}
        self.stubbed_mapped_nics = nic_mapping

        # Mix of commands that should be separated into categories
        bridge_config = """
        type: ovs_bridge
        name: br-test
        ovs_extra:
          - "set interface {name} external_ids:iface-cmd=test"
          - "set port {name} tag=100"
          - "set bridge {name} fail_mode=standalone"
        """

        obj = objects.object_from_json(yaml.safe_load(bridge_config))
        # Should parse successfully - commands get distributed to parsers
        self.provider.add_bridge(obj)

    def test_enhanced_ovs_interface_constructor(self):
        """Test enhanced OvsInterface constructor with ovs_extra parameter"""
        nic_mapping = {'nic1': 'eth0', 'nic2': 'eth1'}
        self.stubbed_mapped_nics = nic_mapping

        # Test the new ovs_extra parameter in OvsInterface
        ovs_extra_cmds = ["set interface {name} external_ids:vm-id=12345"]

        ovs_interface = objects.OvsInterface(
            'test-iface',
            ovs_extra=ovs_extra_cmds
        )

        # Verify the ovs_extra is properly formatted and stored
        expected = ["set interface test-iface external_ids:vm-id=12345"]
        self.assertEqual(expected, ovs_interface.ovs_extra)

        # Test adding it to provider
        self.provider.add_ovs_interface(ovs_interface)

    def test_bridge_features_datapath_type(self):
        """Test datapath_type bridge feature"""
        nic_mapping = {'nic1': 'eth0', 'nic2': 'eth1'}
        self.stubbed_mapped_nics = nic_mapping

        bridge_config = """
        type: ovs_bridge
        name: br-test
        ovs_extra:
          - "set bridge {name} datapath_type=netdev"
        """

        obj = objects.object_from_json(yaml.safe_load(bridge_config))
        self.provider.add_bridge(obj)

        # Verify datapath_type is handled correctly
        bridge_data = self.provider.bridge_data['br-test']
        self.assertIn('datapath',
                      bridge_data['bridge']['options'])

    def test_bridge_features_del_controller(self):
        """Test del-controller command support"""
        nic_mapping = {'nic1': 'eth0', 'nic2': 'eth1'}
        self.stubbed_mapped_nics = nic_mapping

        bridge_config = """
        type: ovs_bridge
        name: br-test
        ovs_extra:
          - "del-controller {name}"
        """

        obj = objects.object_from_json(yaml.safe_load(bridge_config))
        # Should parse successfully - del-controller has empty action list
        self.provider.add_bridge(obj)

    def test_unhandled_command_tracking_edge_case(self):
        """Test edge case where commands don't match any parser category"""
        nic_mapping = {'nic1': 'eth0', 'nic2': 'eth1'}
        self.stubbed_mapped_nics = nic_mapping

        # Command that doesn't match interface, port, or bridge patterns
        bridge_config = """
        type: ovs_bridge
        name: br-test
        ovs_extra:
          - "completely-invalid-command with bad syntax"
        """

        obj = objects.object_from_json(yaml.safe_load(bridge_config))

        # Should raise ConfigurationError for completely unhandled command
        self.assertRaises(os_net_config.ConfigurationError,
                          self.provider.add_bridge, obj)

    def test_get_dpdk_port_pci_address_multiple_ports(self):
        # Test getting PCI addresses for multiple DPDK ports individually
        running_yaml = """
interfaces:
  - name: dpdk0
    type: ovs-interface
    dpdk:
      devargs: '0000:19:06.3'
  - name: dpdk1
    type: ovs-interface
    dpdk:
      devargs: '0000:19:0a.3'
"""

        full_state = yaml.safe_load(running_yaml)

        # Stub iface_state(name) to return only the specific iface dict
        def stub_iface_state(self, name=''):
            if name:
                for iface in full_state['interfaces']:
                    if iface.get('name') == name:
                        return iface
                return None
            return full_state['interfaces']

        self.stub_out(
            'os_net_config.impl_nmstate.NmstateNetConfig.iface_state',
            stub_iface_state
        )

        # Test individual DPDK ports
        pci_addr0 = self.provider._get_dpdk_port_pci_address('dpdk0')
        self.assertEqual(['0000:19:06.3'], pci_addr0)

        pci_addr1 = self.provider._get_dpdk_port_pci_address('dpdk1')
        self.assertEqual(['0000:19:0a.3'], pci_addr1)

    def test_get_dpdk_port_pci_address(self):
        # YAML describing a single dpdk interface with devargs
        running_yaml = """
interfaces:
  - name: dpdk9
    type: ovs-interface
    dpdk:
      devargs: '0000:af:12.7'
"""
        state = yaml.safe_load(running_yaml)

        def stub_iface_state(self, name=''):
            if name:
                for iface in state['interfaces']:
                    if iface.get('name') == name:
                        return iface
                return None
            return state['interfaces']
        self.stub_out(
            'os_net_config.impl_nmstate.NmstateNetConfig.iface_state',
            stub_iface_state
        )

        # The method returns a list with the PCI address
        self.assertEqual(['0000:af:12.7'],
                         self.provider._get_dpdk_port_pci_address('dpdk9'))

    def test_get_dpdk_port_pci_address_no_devargs(self):
        # Test case where DPDK interface has no devargs
        running_yaml = """
interfaces:
  - name: dpdk_no_devargs
    type: ovs-interface
    dpdk: {}
"""
        state = yaml.safe_load(running_yaml)

        def stub_iface_state(self, name=''):
            if name:
                for iface in state['interfaces']:
                    if iface.get('name') == name:
                        return iface
                return None
            return state['interfaces']
        self.stub_out(
            'os_net_config.impl_nmstate.NmstateNetConfig.iface_state',
            stub_iface_state
        )

        # Should return empty list when devargs is missing
        self.assertEqual(
            [],
            self.provider._get_dpdk_port_pci_address('dpdk_no_devargs'))

    def test_get_dpdk_port_pci_address_not_found(self):
        # Test case where interface doesn't exist
        def stub_iface_state(self, name=''):
            return None
        self.stub_out(
            'os_net_config.impl_nmstate.NmstateNetConfig.iface_state',
            stub_iface_state
        )

        # Should return empty list when interface not found
        self.assertEqual(
            [],
            self.provider._get_dpdk_port_pci_address('nonexistent'))


class TestNmstateNetConfigApply(base.TestCase):

    def setUp(self):
        super(TestNmstateNetConfigApply, self).setUp()
        common.set_noop(True)
        impl_nmstate.CONFIG_RULES_FILE = "/tmp/nmstate_files/rules.yaml"

        def test_iface_state(iface_data='', verify_change=True):
            # This function returns None
            return None
        self.stub_out(
            'libnmstate.netapplier.apply', test_iface_state)

        def show_running_info_stub():
            running_info_path = os.path.join(
                os.path.dirname(__file__),
                'environment/netinfo_running_info_1.yaml')
            running_info = self.get_running_info(running_info_path)
            return running_info
        self.stub_out('libnmstate.netinfo.show_running_config',
                      show_running_info_stub)

        self.provider = impl_nmstate.NmstateNetConfig()

        def get_totalvfs_stub(iface_name):
            return 10
        self.stub_out('os_net_config.utils.get_totalvfs',
                      get_totalvfs_stub)

    def add_object(self, nic_config):
        iface_array = yaml.safe_load(nic_config)
        for iface_json in iface_array:
            obj = objects.object_from_json(iface_json)
            self.provider.add_object(obj)

    def get_running_info(self, yaml_file):
        with open(yaml_file) as f:
            data = yaml.load(f, Loader=yaml.SafeLoader)
            return data

    def tearDown(self):
        super(TestNmstateNetConfigApply, self).tearDown()

    def test_base_interface(self):
        self.add_object(_BASE_IFACE_CFG)
        updated_files = self.provider.apply()
        self.assertEqual(yaml.load(_BASE_IFACE_CFG_APPLIED,
                                   Loader=yaml.SafeLoader),
                         updated_files)


class TestNmstateNetConfigDeviceRemoval(base.TestCase):

    def get_running_info(self, yaml_file):
        with open(yaml_file) as f:
            data = yaml.load(f, Loader=yaml.SafeLoader)
            return data

    def setUp(self):
        def show_running_info_stub():
            running_info_path = os.path.join(
                os.path.dirname(__file__),
                'environment/netinfo_running_info_1.yaml')
            running_info = self.get_running_info(running_info_path)
            return running_info
        self.stub_out('libnmstate.netinfo.show_running_config',
                      show_running_info_stub)
        super(TestNmstateNetConfigDeviceRemoval, self).setUp()
        self.provider = impl_nmstate.NmstateNetConfig()

    def test_remove_devices_empty_list(self):
        # Test with empty list
        self.provider.remove_devices([])
        # Should complete without errors

    def test_remove_devices_ordered_processing(self):
        # Test ordered processing of different device types
        devices = [
            objects.RemoveNetDevice('sriov-pf', 'sriov_pf'),
            objects.RemoveNetDevice('bond0', 'linux_bond'),
            objects.RemoveNetDevice('dpdk0', 'ovs_dpdk_port'),
            objects.RemoveNetDevice('dpdkbond0', 'ovs_dpdk_bond'),
            objects.RemoveNetDevice('ovsbond0', 'ovs_bond'),
            objects.RemoveNetDevice('eth0', 'interface'),
            objects.RemoveNetDevice('vlan10', 'vlan'),
            objects.RemoveNetDevice('br0', 'ovs_bridge'),
            objects.RemoveNetDevice('br-user', 'ovs_user_bridge'),
            objects.RemoveNetDevice('vf0', 'sriov_vf')
        ]

        # Mock the processing method to track call order
        processed_devices = []

        def mock_process_device_removal(self, device):
            processed_devices.append((device.remove_name, device.remove_type))
            return

        self.stub_out(
            'os_net_config.impl_nmstate.NmstateNetConfig.'
            '_process_device_removal',
            mock_process_device_removal)

        # Mock backup functionality to avoid permission issues
        self.stub_out('os.makedirs', lambda *args, **kwargs: None)
        self.stub_out('os_net_config.utils.backup_map_files',
                      lambda *args: None)

        self.provider.remove_devices(devices)
        # Verify devices were processed in correct order
        expected_order = [
            ('dpdk0', 'ovs_dpdk_port'),      # DPDK ports first
            ('dpdkbond0', 'ovs_dpdk_bond'),  # DPDK bonds second
            ('ovsbond0', 'ovs_bond'),        # Then OVS bonds
            ('vlan10', 'vlan'),              # Then VLANs
            ('eth0', 'interface'),           # Then interfaces
            ('vf0', 'sriov_vf'),             # Then SR-IOV VFs
            ('br0', 'ovs_bridge'),           # Then OVS bridges
            ('br-user', 'ovs_user_bridge'),  # Then OVS user bridges
            ('bond0', 'linux_bond'),         # Then linux bonds
            ('sriov-pf', 'sriov_pf')         # Finally SR-IOV PFs
        ]
        self.assertEqual(processed_devices, expected_order)

    def test_process_device_removal_noop_mode(self):
        # Test noop mode
        self.provider.noop = True
        device = objects.RemoveNetDevice('eth0', 'interface')

        # Should complete without actual processing
        self.provider._process_device_removal(device)

    def test_process_device_removal_dpdk_port(self):
        # Test DPDK port removal
        device = objects.RemoveNetDevice('dpdk0', 'ovs_dpdk_port')
        # Set provider_data so the device is actually processed
        from os_net_config.impl_nmstate import RemoveDeviceNmstateData
        device.provider_data = RemoveDeviceNmstateData(
            dev_name='dpdk0',
            dev_type=InterfaceType.OVS_INTERFACE,
            pci_address=['0000:05:00.0']
        )

        def mock_remove_dpdk_interface(pci_address):
            assert pci_address == '0000:05:00.0'

        def mock_clean_iface(self, iface_name, nmstate_type):
            assert iface_name == 'dpdk0'
            assert nmstate_type == InterfaceType.OVS_INTERFACE

        self.stub_out(
            'os_net_config.utils.remove_dpdk_interface',
            mock_remove_dpdk_interface)
        self.stub_out(
            'os_net_config.impl_nmstate.NmstateNetConfig._clean_iface',
            mock_clean_iface)

        self.provider._process_device_removal(device)

    def test_process_device_removal_dpdk_bond(self):
        # Test DPDK bond removal
        device = objects.RemoveNetDevice('dpdkbond0', 'ovs_dpdk_bond')
        # Set provider_data so the device is actually processed
        from os_net_config.impl_nmstate import RemoveDeviceNmstateData
        device.provider_data = RemoveDeviceNmstateData(
            dev_name='dpdkbond0',
            dev_type=InterfaceType.OVS_INTERFACE,
            pci_address=['0000:05:00.0', '0000:06:00.0']
        )

        # Track which PCI addresses were removed
        removed_pci_addresses = []

        def mock_remove_dpdk_interface(pci_address):
            removed_pci_addresses.append(pci_address)

        def mock_clean_iface(self, iface_name, nmstate_type):
            assert iface_name == 'dpdkbond0'
            assert nmstate_type == InterfaceType.OVS_INTERFACE

        self.stub_out(
            'os_net_config.utils.remove_dpdk_interface',
            mock_remove_dpdk_interface)
        self.stub_out(
            'os_net_config.impl_nmstate.NmstateNetConfig._clean_iface',
            mock_clean_iface)

        self.provider._process_device_removal(device)
        # Verify both PCI addresses were processed
        self.assertEqual(sorted(removed_pci_addresses),
                         sorted(['0000:05:00.0', '0000:06:00.0']))

    def test_process_device_removal_ovs_user_bridge(self):
        # Test OVS user bridge removal
        device = objects.RemoveNetDevice('br-user', 'ovs_user_bridge')
        # Set provider_data so the device is actually processed
        from os_net_config.impl_nmstate import RemoveDeviceNmstateData
        device.provider_data = RemoveDeviceNmstateData(
            dev_name='br-user',
            dev_type=OVSBridge.TYPE
        )

        def mock_clean_iface(self, iface_name, nmstate_type):
            assert iface_name == 'br-user'
            assert nmstate_type == OVSBridge.TYPE

        self.stub_out(
            'os_net_config.impl_nmstate.NmstateNetConfig._clean_iface',
            mock_clean_iface)

        self.provider._process_device_removal(device)

    def test_remove_devices_with_backup(self):
        # Test backup functionality when removing devices that require backup
        devices = [
            objects.RemoveNetDevice('dpdk0', 'ovs_dpdk_port'),
            objects.RemoveNetDevice('eth0', 'sriov_pf')
        ]

        backup_called = False
        backup_path_created = None

        def mock_backup_map_files(backup_path):
            nonlocal backup_called, backup_path_created
            backup_called = True
            backup_path_created = backup_path

        def mock_makedirs(path, exist_ok=False):
            pass

        def mock_get_timestamp():
            return "20240101_120000"

        # Mock the backup functions
        self.stub_out('os_net_config.utils.backup_map_files',
                      mock_backup_map_files)
        self.stub_out('os.makedirs', mock_makedirs)
        self.stub_out('os_net_config.common.get_timestamp', mock_get_timestamp)

        # Mock device processing to avoid actual operations
        def mock_process_device_removal(self, device):
            return
        self.stub_out(
            'os_net_config.impl_nmstate.NmstateNetConfig.'
            '_process_device_removal',
            mock_process_device_removal)

        result = self.provider.remove_devices(devices)

        # Verify backup was called
        self.assertTrue(backup_called)
        self.assertIn("20240101_120000", backup_path_created)
        self.assertEqual(0, result)

    def test_remove_devices_no_backup_needed(self):
        # Test no backup when devices don't require it
        devices = [
            objects.RemoveNetDevice('eth0', 'interface'),
            objects.RemoveNetDevice('br0', 'ovs_bridge')
        ]

        backup_called = False

        def mock_backup_map_files(backup_path):
            nonlocal backup_called
            backup_called = True

        # Mock the backup function
        self.stub_out('os_net_config.utils.backup_map_files',
                      mock_backup_map_files)

        # Mock device processing to avoid actual operations
        def mock_process_device_removal(self, device):
            return
        self.stub_out(
            'os_net_config.impl_nmstate.NmstateNetConfig.'
            '_process_device_removal',
            mock_process_device_removal)

        result = self.provider.remove_devices(devices)

        # Verify backup was NOT called
        self.assertFalse(backup_called)
        self.assertEqual(0, result)

    def test_remove_devices_backup_noop_mode(self):
        # Test backup intent logged but not executed in noop mode
        self.provider.noop = True
        devices = [objects.RemoveNetDevice('dpdk0', 'ovs_dpdk_port')]

        backup_called = False

        def mock_backup_map_files(backup_path):
            nonlocal backup_called
            backup_called = True

        # Mock the backup function
        self.stub_out('os_net_config.utils.backup_map_files',
                      mock_backup_map_files)

        self.provider.remove_devices(devices)

        # Verify backup was NOT called in noop mode
        self.assertFalse(backup_called)

    def test_process_device_removal_sriov_pf(self):
        # Test SR-IOV PF removal
        device = objects.RemoveNetDevice('eth0', 'sriov_pf')
        # Set provider_data so the device is actually processed
        from os_net_config.impl_nmstate import RemoveDeviceNmstateData
        device.provider_data = RemoveDeviceNmstateData(
            dev_name='eth0',
            dev_type=InterfaceType.ETHERNET
        )

        def mock_remove_entries_for_sriov_dev(pfname):
            assert pfname == 'eth0'

        def mock_clean_iface(self, iface_name, nmstate_type):
            assert iface_name == 'eth0'
            assert nmstate_type == InterfaceType.ETHERNET

        self.stub_out(
            'os_net_config.utils.remove_entries_for_sriov_dev',
            mock_remove_entries_for_sriov_dev)
        self.stub_out(
            'os_net_config.impl_nmstate.NmstateNetConfig._clean_iface',
            mock_clean_iface)

        self.provider._process_device_removal(device)
