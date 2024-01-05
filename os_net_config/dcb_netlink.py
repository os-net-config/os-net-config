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

from pyroute2.netlink import nla
from pyroute2.netlink import nlmsg

# DCB Commands
DCB_CMD_IEEE_SET = 20
DCB_CMD_IEEE_GET = 21
DCB_CMD_GDCBX = 22
DCB_CMD_SDCBX = 23
DCB_CMD_IEEE_DEL = 27

# DSCP Selector
IEEE_8021QAZ_APP_SEL_DSCP = 5


class dcbmsg(nlmsg):

    pack = 'struct'

    """C Structure
    struct dcbmsg {
        __u8    dcb_family;
        __u8    cmd;
        __u16   dcb_pad;
    };
    """
    fields = (
        ('family', 'B'),
        ('cmd', 'B'),
        ('pad', 'H'),
    )
    nla_map = (
        (1, 'DCB_ATTR_IFNAME', 'asciiz'),
        (13, 'DCB_ATTR_IEEE', 'ieee_attrs'),
        (14, 'DCB_ATTR_DCBX', 'uint8'),
    )

    class ieee_attrs(nla):
        pack = 'struct'
        nla_map = (
            (1, 'DCB_ATTR_IEEE_ETS', 'ieee_ets'),
            (2, 'DCB_ATTR_IEEE_PFC', 'ieee_pfc'),
            (3, 'DCB_ATTR_IEEE_APP_TABLE', 'ieee_app_table'),
            )

        """This structure contains the IEEE 802.1Qaz ETS managed object

            :willing: willing bit in ETS configuration TLV
            :ets_cap: indicates supported capacity of ets feature
            :cbs: credit based shaper ets algorithm supported
            :tc_tx_bw: tc tx bandwidth indexed by traffic class
            :tc_rx_bw: tc rx bandwidth indexed by traffic class
            :tc_tsa: TSA Assignment table, indexed by traffic class
            :prio_tc: priority assignment table mapping 8021Qp to tc
            :tc_reco_bw: recommended tc bw indexed by tc for TLV
            :tc_reco_tsa: recommended tc bw indexed by tc for TLV
            :reco_prio_tc: recommended tc tx bw indexed by tc for TLV

            Recommended values are used to set fields in the ETS
            recommendation TLV with hardware offloaded LLDP.

            ----
             TSA Assignment 8 bit identifiers
                 0        strict priority
                 1        credit-based shaper
                 2        enhanced transmission selection
                 3-254    reserved
                 255      vendor specific
        """
        class ieee_ets(nla):
            pack = 'struct'
            fields = (
                ('willing', 'B'),
                ('ets_cap', 'B'),
                ('cbs', 'B'),
                ('tc_tx_bw', 'BBBBBBBB'),
                ('tc_rx_bw', 'BBBBBBBB'),
                ('tc_tsa', 'BBBBBBBB'),
                ('prio_tc', 'BBBBBBBB'),
                ('tc_reco_bw', 'BBBBBBBB'),
                ('tc_reco_tsa', 'BBBBBBBB'),
                ('reco_prio_tc', 'BBBBBBBB'),
            )

        class ieee_app_table(nla):
            pack = 'struct'
            nla_map = (
                (0, 'DCB_ATTR_IEEE_APP_UNSPEC', 'none'),
                (1, 'DCB_ATTR_IEEE_APP', 'dcb_app'),
                )

            """This structure contains the IEEE 802.1Qaz APP managed object. This
            object is also used for the CEE std as well.

            :selector: protocol identifier type
            :protocol: protocol of type indicated
            :priority: 3-bit unsigned integer indicating priority for IEEE
                       8-bit 802.1p user priority bitmap for CEE
            """
            class dcb_app(nla):
                pack = 'struct'
                fields = (
                    ('selector', 'B'),
                    ('priority', 'B'),
                    ('protocol', 'H'),
                    )

        """This structure contains the IEEE 802.1Qaz PFC managed object

        :pfc_cap: Indicates the number of traffic classes on the local device
                  that may simultaneously have PFC enabled.
        :pfc_en: bitmap indicating pfc enabled traffic classes
        :mbc: enable macsec bypass capability
        :delay: the allowance made for a round-trip propagation delay of the
                link in bits.
        :requests: count of the sent pfc frames
        :indications: count of the received pfc frames
        """
        class ieee_pfc(nla):
            pack = 'struct'
            fields = (
                ('pfc_cap', 'B'),
                ('pfc_en', 'B'),
                ('mbc', 'B'),
                ('delay', 'H'),
                ('requests', 'QQQQQQQQ'),
                ('indications', 'QQQQQQQQ'),
            )
