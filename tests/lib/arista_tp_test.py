# Copyright 2020 Arista Networks Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""unittest for arista traffic-policy rendering module."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import datetime
import re
import unittest

import mock

# from absl import logging
from capirca.lib import aclgenerator
from capirca.lib import arista_tp
from capirca.lib import nacaddr
from capirca.lib import naming
from capirca.lib import policy

# from six.moves import range

# import pprint as ppr

GOOD_HEADER = """
header {
  comment:: "this is a test acl"
  target:: arista_tp test-filter
}
"""
GOOD_HEADER_INET = """
header {
  comment:: "test inet acl"
  target:: arista_tp test-filter inet
}
"""

GOOD_HEADER_INET6 = """
header {
  comment:: "this is a test acl"
  target:: arista_tp test-filter inet6
}
"""

GOOD_NOVERBOSE_MIXED_HEADER = """
header {
  target:: arista_tp test-filter noverbose
}
"""
GOOD_NOVERBOSE_V4_HEADER = """
header {
  target:: arista_tp test-filter inet noverbose
}
"""

GOOD_NOVERBOSE_V6_HEADER = """
header {
  target:: arista_tp test-filter inet6 noverbose
}
"""
BAD_HEADER = """
header {
  comment:: "this is a test acl"
  target:: cisco test-filter
}
"""

BAD_HEADER_2 = """
header {
  target:: arista_tp test-filter inetfoo
}
"""

EXPIRED_TERM = """
term is_expired {
  expiration:: 2001-01-01
  action:: accept
}
"""
EXPIRING_TERM = """
term is_expiring {
  expiration:: %s
  action:: accept
}
"""
GOOD_TERM_1 = """
term good-term-1 {
  protocol:: icmp
  action:: accept
}

term good-term-2 {
  protocol:: tcp
  destination-port:: SMTP
  destination-address:: SOME_HOST
  action:: accept
}
"""
GOOD_TERM_1_V6 = """
term good-term-1 {
  protocol:: icmpv6
  action:: accept
}

term good-term-2 {
  protocol:: tcp
  destination-port:: SMTP
  destination-address:: SOME_HOST
  action:: accept
}
"""
GOOD_TERM_2 = """
term good-term-3 {
  protocol:: tcp
  destination-address:: SOME_HOST
  source-port:: HTTP
  option:: established tcp-established
  action:: accept
}
"""
GOOD_TERM_3 = """
term good-term-3 {
  protocol:: icmp
  icmp-type:: echo-reply information-reply information-request
  icmp-type:: router-solicitation timestamp-request
  action:: accept
}
"""
GOOD_TERM_5 = """
term good-term-5 {
  protocol:: icmp
  protocol:: tcp
  action:: accept
}
"""

GOOD_TERM_7 = """
term good-term-7 {
  protocol-except:: tcp
  action:: accept
}
"""
GOOD_TERM_8 = """
term good-term-8 {
  source-prefix:: foo_prefix_list
  destination-prefix:: bar_prefix_list baz_prefix_list
  action:: accept
}
"""
GOOD_TERM_9 = """
term good-term-9 {
  ether-type:: arp
  action:: accept
}
"""
GOOD_TERM_10 = """
term good-term-10 {
  traffic-type:: unknown-unicast
  action:: accept
}
"""
GOOD_TERM_11 = """
term good-term-11 {
  verbatim:: arista_tp "mary had a little lamb"
  verbatim:: iptables "mary had a second lamb"
  verbatim:: cisco "mary had a third lamb"
}
"""
GOOD_TERM_12 = """
term good-term-12 {
  source-address:: LOCALHOST
  action:: accept
}
"""
GOOD_TERM_17 = """
term owner-term {
  owner:: foo@google.com
  action:: accept
}
"""
GOOD_TERM_18_SRC = """
term address-exclusions {
  source-address:: INTERNAL
  source-exclude:: SOME_HOST
  action:: accept
}
"""
GOOD_TERM_18_DST = """
term address-exclusions {
  destination-address:: INTERNAL
  destination-exclude:: SOME_HOST
  action:: accept
}
"""
GOOD_TERM_19 = """
term minimize-prefix-list {
  source-address:: INCLUDES
  source-exclude:: EXCLUDES
  action:: accept
}
"""
GOOD_TERM_V6_HOP_LIMIT = """
term good-term-v6-hl {
  hop-limit:: 25
  action:: accept
}
"""
GOOD_TERM_20_V6 = """
term good-term-20-v6 {
  protocol-except:: icmpv6
  action:: accept
}
"""
GOOD_TERM_21 = """
term good_term_21 {
  ttl:: 10
  action:: accept
}
"""
GOOD_TERM_22 = """
term good_term_22 {
  protocol:: tcp
  source-port:: DNS
  dscp-set:: b111000
  action:: accept
}
"""
GOOD_TERM_23 = """
term good_term_23 {
  protocol:: tcp
  source-port:: DNS
  dscp-set:: af42
  dscp-match:: af41-af42 5
  dscp-except:: be
  action:: accept
}
"""
GOOD_TERM_24 = """
term good_term_24 {
  protocol:: tcp
  source-port:: DNS
  qos:: af1
  action:: accept
}
"""
GOOD_TERM_25 = """
term good_term_25 {
  protocol:: tcp
  source-port:: DNS
  action:: accept
}
"""
GOOD_TERM_26 = """
term good_term_26 {
  protocol:: tcp
  source-port:: DNS
  action:: deny
}
"""
GOOD_TERM_26_V6 = """
term good_term_26-v6 {
  protocol:: tcp
  source-port:: DNS
  action:: deny
}
"""
GOOD_TERM_26_V6_REJECT = """
term good_term_26-v6 {
  protocol:: tcp
  source-port:: DNS
  action:: reject
}
"""
GOOD_TERM_27 = """
term good_term_27 {
  forwarding-class:: Floop
  action:: deny
}
"""
GOOD_TERM_28 = """
term good_term_28 {
  action:: accept
}
"""
GOOD_TERM_30 = """
term good-term-30 {
  source-prefix-except:: foo_prefix_list
  destination-prefix-except:: bar_prefix_list
  action:: accept
}
"""
GOOD_TERM_31 = """
term good-term-31 {
  source-prefix:: foo_prefix
  source-prefix-except:: foo_except
  destination-prefix:: bar_prefix
  destination-prefix-except:: bar_except
  action:: accept
}
"""
GOOD_TERM_32 = """
term good_term_32 {
  forwarding-class-except:: floop
  action:: deny
}
"""
GOOD_TERM_34 = """
term good_term_34 {
  traffic-class-count:: floop
  action:: deny
}
"""
GOOD_TERM_35 = """
term good_term_35 {
  protocol:: icmp
  icmp-type:: unreachable
  icmp-code:: 3 4
  action:: accept
}
"""
GOOD_TERM_36 = """
term good-term-36 {
  protocol:: tcp
  destination-address:: SOME_HOST
  destination-address:: SOME_HOST
  option:: inactive
  action:: accept
}
"""
GOOD_TERM_COMMENT = """
term good-term-comment {
  comment:: "This is a COMMENT"
  action:: accept
}
"""
BAD_TERM_1 = """
term bad-term-1 {
  protocol:: tcp udp
  source-port:: DNS
  option:: tcp-established
  action:: accept
}
"""
ESTABLISHED_TERM_1 = """
term established-term-1 {
  protocol:: tcp
  source-port:: DNS
  option:: established
  action:: accept
}
"""
OPTION_TERM_1 = """
term option-term {
  protocol:: tcp
  source-port:: SSH
  option:: is-fragment
  action:: accept
}
"""
BAD_ICMPTYPE_TERM_1 = """
term icmptype-mismatch {
  comment:: "error when icmpv6 paired with inet filter"
  protocol:: icmpv6
  icmp-type:: echo-request echo-reply
  action:: accept
}
"""
BAD_ICMPTYPE_TERM_2 = """
term icmptype-mismatch {
  comment:: "error when icmp paired with inet6 filter"
  protocol:: icmp
  icmp-type:: echo-request echo-reply
  action:: accept
}
"""
DEFAULT_TERM_1 = """
term default-term-1 {
  action:: deny
}
"""
ENCAPSULATE_GOOD_TERM_1 = """
term good-term-1 {
  protocol:: tcp
  encapsulate:: template-name
}
"""
ENCAPSULATE_GOOD_TERM_2 = """
term good-term-2 {
  protocol:: tcp
  encapsulate:: template-name
  counter:: count-name
}
"""
ENCAPSULATE_BAD_TERM_1 = """
term bad-term-1 {
  protocol:: tcp
  encapsulate:: template-name
  action:: accept
}
"""
ENCAPSULATE_BAD_TERM_2 = """
term bad-term-2 {
  protocol:: tcp
  encapsulate:: template-name
  routing-instance:: instance-name
}
"""
LONG_COMMENT_TERM_1 = """
term long-comment-term-1 {
  comment:: "this is very very very very very very very very very very very
  comment:: "very very very very very very very long."
  action:: deny
}
"""
LONG_POLICER_TERM_1 = """
term long-policer-term-1 {
  policer:: this-is-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-long
  action:: deny
}
"""
HOPOPT_TERM = """
term good-term-1 {
  protocol:: hopopt
  action:: accept
}
"""
FRAGOFFSET_TERM = """
term good-term-1 {
  fragment-offset:: 1-7
  action:: accept
}
"""
MIXED_INET = """
term MIXED_INET {
  source-address:: GOOGLE_DNS
  destination-address:: INTERNAL
  protocol:: tcp udp
  action:: accept
}
  """

INET_MIXED = """
  term INET_MIXED {
    source-address:: INTERNAL
    destination-address:: GOOGLE_DNS
    protocol:: tcp udp
    action:: accept
  }
  """

MIXED_INET6 = """
  term MIXED_INET6 {
    source-address:: GOOGLE_DNS
    destination-address:: SOME_HOST
    action:: accept
  }
  """

INET6_MIXED = """
  term INET6_MIXED {
    source-address:: SOME_HOST
    destination-address:: GOOGLE_DNS
    action:: accept
  }
  """

MIXED_MIXED = """
  term MIXED_MIXED {
    source-address:: GOOGLE_DNS
    destination-address:: GOOGLE_DNS
    action:: accept
  }
  """

MIXED_ANY = """
  term MIXED_ANY {
    source-address:: GOOGLE_DNS
    action:: accept
  }
  """

ANY_MIXED = """
  term ANY_MIXED {
    destination-address:: GOOGLE_DNS
    action:: accept
  }
  """

INET_INET = """
  term INET_INET {
    source-address:: NTP_SERVERS
    destination-address:: INTERNAL
    action:: accept
  }
  """

INET6_INET6 = """
  term INET6_INET6 {
    source-address:: SOME_HOST
    destination-address:: SOME_HOST
    action:: accept
  }
  """

INET_INET6 = """
  term INET_INET6 {
    source-address:: INTERNAL
    destination-address:: SOME_HOST
    action:: accept
  }
  """

INET6_INET = """
  term INET6_INET {
    source-address:: SOME_HOST
    destination-address:: INTERNAL
    action:: accept
  }
  """

SUPPORTED_TOKENS = frozenset(
    [
        "action",
        "address",
        "comment",
        "counter",
        "destination_address",
        "destination_address_exclude",
        "destination_port",
        "destination_prefix",
        "dscp_set",
        "expiration",
        "fragment_offset",
        "hop_limit",
        "icmp_code",
        "icmp_type",
        "logging",
        "name",
        "option",
        "owner",
        "packet_length",
        "platform",
        "platform_exclude",
        "port",
        "protocol",
        "protocol_except",
        "source_address",
        "source_address_exclude",
        "source_port",
        "source_prefix",
        "stateless_reply",
        "translated",
        "ttl",
        "verbatim",
    ]
)

SUPPORTED_SUB_TOKENS = {
    "action": {"accept", "deny", "reject", "next", "reject-with-tcp-rst"},
    "icmp_type": {
        "alternate-address",
        "certification-path-advertisement",
        "certification-path-solicitation",
        "conversion-error",
        "destination-unreachable",
        "echo-reply",
        "echo-request",
        "mobile-redirect",
        "home-agent-address-discovery-reply",
        "home-agent-address-discovery-request",
        "icmp-node-information-query",
        "icmp-node-information-response",
        "information-request",
        "inverse-neighbor-discovery-advertisement",
        "inverse-neighbor-discovery-solicitation",
        "mask-reply",
        "mask-request",
        "information-reply",
        "mobile-prefix-advertisement",
        "mobile-prefix-solicitation",
        "multicast-listener-done",
        "multicast-listener-query",
        "multicast-listener-report",
        "multicast-router-advertisement",
        "multicast-router-solicitation",
        "multicast-router-termination",
        "neighbor-advertisement",
        "neighbor-solicit",
        "packet-too-big",
        "parameter-problem",
        "redirect",
        "redirect-message",
        "router-advertisement",
        "router-renumbering",
        "router-solicit",
        "router-solicitation",
        "source-quench",
        "time-exceeded",
        "timestamp-reply",
        "timestamp-request",
        "unreachable",
        "version-2-multicast-listener-report",
    },
    "option": {
        "established",
        "is-fragment",
        ".*",  # not actually a lex token!
        "tcp-established",
        "tcp-initial",
    },
}

# print an info message when a term is set to expire in that many weeks.
# normally passed from command line.
EXP_INFO = 2


class AristaTpTest(unittest.TestCase):
    def setUp(self):
        super(AristaTpTest, self).setUp()
        self.naming = mock.create_autospec(naming.Naming)

    def testOptions(self):
        self.naming.GetNetAddr.return_value = [nacaddr.IP("10.0.0.0/8")]
        self.naming.GetServiceByProto.return_value = ["80"]

        atp = arista_tp.AristaTrafficPolicy(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_2, self.naming), EXP_INFO
        )
        output = str(atp)
        self.assertIn("destination port 1024-65535", output, output)
        # verify that tcp-established; doesn't get duplicated if both 'established'
        # and 'tcp-established' options are included in term
        self.assertEqual(output.count("established"), 1)

        self.naming.GetNetAddr.assert_called_once_with("SOME_HOST")
        self.naming.GetServiceByProto.assert_called_once_with("HTTP", "tcp")

    def testTermAndFilterName(self):
        self.naming.GetNetAddr.return_value = [nacaddr.IP("10.0.0.0/8")]
        self.naming.GetServiceByProto.return_value = ["25"]

        atp = arista_tp.AristaTrafficPolicy(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_1, self.naming), EXP_INFO
        )
        output = str(atp)
        self.assertIn("match good-term-1", output, output)
        self.assertIn("traffic-policy test-filter", output, output)

        self.naming.GetNetAddr.assert_called_once_with("SOME_HOST")
        self.naming.GetServiceByProto.assert_called_once_with("SMTP", "tcp")

    def testBadFilterType(self):
        self.naming.GetNetAddr.return_value = [nacaddr.IP("10.0.0.0/8")]
        self.naming.GetServiceByProto.return_value = ["25"]

        pol = policy.ParsePolicy(BAD_HEADER_2 + GOOD_TERM_1, self.naming)
        self.assertRaises(
            aclgenerator.UnsupportedAFError,
            arista_tp.AristaTrafficPolicy,
            pol,
            EXP_INFO,
        )

        self.naming.GetNetAddr.assert_called_once_with("SOME_HOST")
        self.naming.GetServiceByProto.assert_called_once_with("SMTP", "tcp")

        # def testDefaultDeny(self):
        #   atp = arista_tp.AristaTrafficPolicy(policy.ParsePolicy(GOOD_HEADER + DEFAULT_TERM_1,
        #                                            self.naming), EXP_INFO)
        #   output = str(atp)
        #   self.assertNotIn('from {', output, output)

        def testIcmpType(self):
            atp = arista_tp.AristaTrafficPolicy(
                policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_3, self.naming), EXP_INFO
            )
            output = str(atp)
            # verify proper translation from policy icmp-type text to traffic-policy
            self.assertIn("icmp type ", output, output)
            self.assertIn("0,", output, output)
            self.assertIn("15,", output, output)
            self.assertIn("10,", output, output)
            self.assertIn("13,", output, output)
            self.assertIn("16,", output, output)

    def testIcmpCode(self):
        atp = arista_tp.AristaTrafficPolicy(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_35, self.naming), EXP_INFO
        )
        output = str(atp)
        self.assertIn("code 3,4", output, output)

    def testInet6(self):
        self.naming.GetNetAddr.return_value = [nacaddr.IP("2001::/33")]
        self.naming.GetServiceByProto.return_value = ["25"]

        atp = arista_tp.AristaTrafficPolicy(
            policy.ParsePolicy(GOOD_HEADER_INET6 + GOOD_TERM_1_V6, self.naming), EXP_INFO
        )
        output = str(atp)
        self.assertTrue(
            "protocol icmpv6" in output and "protocol tcp" in output, output
        )

        self.naming.GetNetAddr.assert_called_once_with("SOME_HOST")
        self.naming.GetServiceByProto.assert_called_once_with("SMTP", "tcp")

    def testHopLimit(self):
        atp = arista_tp.AristaTrafficPolicy(
            policy.ParsePolicy(GOOD_HEADER_INET6 + GOOD_TERM_V6_HOP_LIMIT, self.naming),
            EXP_INFO,
        )
        output = str(atp)
        self.assertIn("ttl 25", output, output)

    # def testProtocolExcept(self):
    #   atp = arista_tp.AristaTrafficPolicy(policy.ParsePolicy(GOOD_HEADER_INET6 + GOOD_TERM_7,
    #                                            self.naming), EXP_INFO)
    #   output = str(atp)
    #   self.assertIn('next-header-except tcp;', output, output)

    # def testIcmpv6Except(self):
    #   atp = arista_tp.AristaTrafficPolicy(policy.ParsePolicy(GOOD_HEADER_INET6 + GOOD_TERM_20_V6,
    #                                            self.naming), EXP_INFO)
    #   output = str(atp)
    #   self.assertIn('next-header-except icmpv6;', output, output)

    def testProtocolCase(self):
        atp = arista_tp.AristaTrafficPolicy(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_5, self.naming), EXP_INFO
        )
        output = str(atp)
        self.assertIn("protocol icmp tcp", output, output)

    def testPrefixList(self):
        atp = arista_tp.AristaTrafficPolicy(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_8, self.naming), EXP_INFO
        )
        spfx_re = re.compile(r"source address\W+foo_prefix_list\W+")
        dpfx_re = re.compile(
            r"destination address\W+bar_prefix_list\W+baz_prefix_list\W+"
        )
        output = str(atp)
        self.assertTrue(spfx_re.search(output), output)
        self.assertTrue(dpfx_re.search(output), output)

    # TODO(sulrich): do we need to support this?
    # def testPrefixListExcept(self):
    #   atp = arista_tp.AristaTrafficPolicy(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_30,
    #                                            self.naming), EXP_INFO)
    #   spfx_re = re.compile(r'source address\W+except\W+foo_prefix_list except\W+')
    #   dpfx_re = re.compile(
    #       r'destination address\W+except\W+bar_prefix_list\W+')
    #   output = str(atp)
    #   self.assertTrue(spfx_re.search(output), output)
    #   self.assertTrue(dpfx_re.search(output), output)

    # def testPrefixListMixed(self):
    #   atp = arista_tp.AristaTrafficPolicy(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_31,
    #                                            self.naming), EXP_INFO)
    #   spfx_re = re.compile(r'source-prefix-list {\W+foo_prefix;\W+'
    #                        r'foo_except except;\W+}')
    #   dpfx_re = re.compile(r'destination-prefix-list {\W+bar_prefix;\W+'
    #                        r'bar_except except;\W+}')
    #   output = str(atp)
    #   self.assertTrue(spfx_re.search(output), output)
    #   self.assertTrue(dpfx_re.search(output), output)

    # def testEtherType(self):
    #   atp = arista_tp.AristaTrafficPolicy(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_9,
    #                                            self.naming), EXP_INFO)
    #   output = str(atp)
    #   self.assertIn('ether-type arp;', output, output)

    def testVerbatimTerm(self):
        atp = arista_tp.AristaTrafficPolicy(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_11, self.naming), EXP_INFO
        )
        output = str(atp)
        self.assertIn("mary had a little lamb", output, output)
        # check if other platforms verbatim shows up in output
        self.assertNotIn("mary had a second lamb", output, output)
        self.assertNotIn("mary had a third lamb", output, output)

    def testTcpEstablished(self):
        self.naming.GetServiceByProto.return_value = ["53"]

        policy_text = GOOD_HEADER + ESTABLISHED_TERM_1
        atp = arista_tp.AristaTrafficPolicy(
            policy.ParsePolicy(policy_text, self.naming), EXP_INFO
        )
        output = str(atp)
        self.assertIn("established", output, output)

        self.naming.GetServiceByProto.assert_called_once_with("DNS", "tcp")

    def testNonTcpWithTcpEstablished(self):
        self.naming.GetServiceByProto.return_value = ["53"]

        policy_text = GOOD_HEADER + BAD_TERM_1
        pol_obj = policy.ParsePolicy(policy_text, self.naming)
        atp = arista_tp.AristaTrafficPolicy(pol_obj, EXP_INFO)
        self.assertRaises(arista_tp.TcpEstablishedWithNonTcpError, str, atp)

        self.naming.GetServiceByProto.assert_has_calls(
            [mock.call("DNS", "tcp"), mock.call("DNS", "udp")]
        )

    def testNoVerboseV4(self):
      addr_list = list()
      for octet in range(0, 256):
        net = nacaddr.IP('192.168.' + str(octet) + '.64/27')
        addr_list.append(net)
      self.naming.GetNetAddr.return_value = addr_list
      self.naming.GetServiceByProto.return_value = ['25']

      atp = arista_tp.AristaTrafficPolicy(
          policy.ParsePolicy(
              GOOD_NOVERBOSE_V4_HEADER + GOOD_TERM_1 + GOOD_TERM_COMMENT,
              self.naming), EXP_INFO)
      self.assertIn('192.168.0.64/27', str(atp))
      self.assertNotIn('COMMENT', str(atp))
      self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
      self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

    def testNoVerboseV6(self):
      addr_list = list()
      for octet in range(0, 256):
        net = nacaddr.IPv6('2001:db8:1010:' + str(octet) + '::64/64',
                           strict=False)
        addr_list.append(net)
      self.naming.GetNetAddr.return_value = addr_list
      self.naming.GetServiceByProto.return_value = ['25']

      atp = arista_tp.AristaTrafficPolicy(
          policy.ParsePolicy(
              GOOD_NOVERBOSE_V6_HEADER + GOOD_TERM_1 + GOOD_TERM_COMMENT,
              self.naming), EXP_INFO)
      self.assertIn('2001:db8:1010:90::/61', str(atp))
      self.assertNotIn('COMMENT', str(atp))
      self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
      self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

    def testTermTypeIndexKeys(self):
      # ensure an _INET entry for each _TERM_TYPE entry
      self.assertEqual(sorted(arista_tp.Term._TERM_TYPE.keys()),
                       sorted(arista_tp.Term.AF_MAP.keys()))

    def testArbitraryOptions(self):
        self.naming.GetServiceByProto.return_value = ["22"]

        atp = arista_tp.AristaTrafficPolicy(
            policy.ParsePolicy(GOOD_HEADER + OPTION_TERM_1, self.naming), EXP_INFO
        )
        output = str(atp)
        self.assertIn("fragment", output, output)

        self.naming.GetServiceByProto.assert_called_once_with("SSH", "tcp")

    @mock.patch.object(arista_tp.logging, "debug")
    def testIcmpv6InetMismatch(self, mock_debug):
        atp = arista_tp.AristaTrafficPolicy(
            policy.ParsePolicy(GOOD_HEADER + BAD_ICMPTYPE_TERM_1, self.naming), EXP_INFO
        )
        str(atp)

        mock_debug.assert_called_once_with(
            "Term icmptype-mismatch will not be rendered,"
            " as it has icmpv6 match specified but "
            "the ACL is of inet address family."
        )

    @mock.patch.object(arista_tp.logging, "debug")
    def testIcmpInet6Mismatch(self, mock_debug):
        atp = arista_tp.AristaTrafficPolicy(
            policy.ParsePolicy(GOOD_HEADER_INET6 + BAD_ICMPTYPE_TERM_2, self.naming),
            EXP_INFO,
        )
        # output happens in __str__
        str(atp)

        mock_debug.assert_called_once_with(
            "Term icmptype-mismatch will not be rendered,"
            " as it has icmp match specified but "
            "the ACL is of inet6 address family."
        )

    @mock.patch.object(arista_tp.logging, "warning")
    def testExpiredTerm(self, mock_warn):
        _ = arista_tp.AristaTrafficPolicy(
            policy.ParsePolicy(GOOD_HEADER + EXPIRED_TERM, self.naming), EXP_INFO
        )

        # mock_warn.assert_called_once_with(
        # mock_warn.assert_called_with(
        #     "WARNING: term %s in policy %s is expired and will " "not be rendered.",
        #     "is_expired",
        #     "test-filter",
        # )
        mock_warn.assert_called_with(
            "WARNING: term %s in policy %s is expired and will " "not be rendered.",
            "is_expired_v6",
            "test-filter",
        )

    @mock.patch.object(arista_tp.logging, "info")
    def testExpiringTerm(self, mock_info):
        exp_date = datetime.date.today() + datetime.timedelta(weeks=EXP_INFO)
        _ = arista_tp.AristaTrafficPolicy(
            policy.ParsePolicy(
                GOOD_HEADER + EXPIRING_TERM % exp_date.strftime("%Y-%m-%d"), self.naming
            ),
            EXP_INFO,
        )

        mock_info.assert_called_once_with(
            "INFO: term %s in policy %s expires in " "less than two weeks.",
            "is_expiring",
            "test-filter",
        )

    def testOwnerTerm(self):
        atp = arista_tp.AristaTrafficPolicy(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_17, self.naming), EXP_INFO
        )
        output = str(atp)
        self.assertIn("!! owner: foo@google.com", output, output)

    # def testAddressExclude(self):
    #   big = nacaddr.IPv4('0.0.0.0/1')
    #   ip1 = nacaddr.IPv4('10.0.0.0/8')
    #   ip2 = nacaddr.IPv4('172.16.0.0/12')
    #   terms = (GOOD_TERM_18_SRC, GOOD_TERM_18_DST)
    #   self.naming.GetNetAddr.side_effect = [[big, ip1, ip2], [ip1]] * len(terms)

    #   mock_calls = []
    #   for term in terms:
    #     atp = arista_tp.AristaTrafficPolicy(
    #         policy.ParsePolicy(GOOD_HEADER + term, self.naming),
    #         EXP_INFO)
    #     output = str(atp)
    #     self.assertIn('10.0.0.0/8 except;', output, output)
    #     self.assertNotIn('10.0.0.0/8;', output, output)
    #     self.assertIn('172.16.0.0/12;', output, output)
    #     self.assertNotIn('172.16.0.0/12 except;', output, output)
    #     mock_calls.append(mock.call('INTERNAL'))
    #     mock_calls.append(mock.call('SOME_HOST'))

    #   self.naming.GetNetAddr.assert_has_calls(mock_calls)

    def testMixedInet(self):
        self.naming.GetNetAddr.side_effect = [
            [nacaddr.IP('8.8.4.4'), nacaddr.IP('8.8.8.8'),
             nacaddr.IP('2001:4860:4860::8844'),
             nacaddr.IP('2001:4860:4860::8888')],
            [nacaddr.IP('10.0.0.0/8'), nacaddr.IP('172.16.0.0/12'),
             nacaddr.IP('192.168.0.0/16')]]

        pol = policy.ParsePolicy(GOOD_HEADER + MIXED_INET, self.naming)
        atp = arista_tp.AristaTrafficPolicy(pol, EXP_INFO)
        output = str(atp)
        self.assertIn("match MIXED_INET ipv4", output, output)
        self.assertIn("source prefix 8.8.4.4/32", output, output)
        self.assertIn("destination prefix 10.0.0.0/8", output, output)

    def testInetMixed(self):
        self.naming.GetNetAddr.side_effect = [
            [nacaddr.IP('10.0.0.0/8'), nacaddr.IP('172.16.0.0/12'),
             nacaddr.IP('192.168.0.0/16')],
            [nacaddr.IP('8.8.4.4'), nacaddr.IP('8.8.8.8'),
             nacaddr.IP('2001:4860:4860::8844'),
             nacaddr.IP('2001:4860:4860::8888')],
        ]

        atp = arista_tp.AristaTrafficPolicy(
            policy.ParsePolicy(GOOD_HEADER + INET_MIXED, self.naming), EXP_INFO
        )
        output = str(atp)
        self.assertIn("match INET_MIXED ipv4", output, output)
        self.assertIn("source prefix 10.0.0.0/8", output, output)
        self.assertIn("destination prefix 8.8.4.4/32", output, output)

    def testMixedInet6(self):
        self.naming.GetNetAddr.side_effect = [
            [nacaddr.IP('8.8.4.4'), nacaddr.IP('8.8.8.8'),
             nacaddr.IP('2001:4860:4860::8844'),
             nacaddr.IP('2001:4860:4860::8888')],
            [nacaddr.IP('2001:4860:4860::8844')]
        ]
        atp = arista_tp.AristaTrafficPolicy(
            policy.ParsePolicy(GOOD_HEADER + MIXED_INET6, self.naming),
            EXP_INFO
        )
        output = str(atp)
        # note that the term name will contain the '_v6' suffix
        self.assertIn("match MIXED_INET6_v6 ipv6", output, output)
        self.assertIn("source prefix 2001:4860:4860::8844/128",
                      output, output)
        self.assertIn("destination prefix 2001:4860:4860::8844/128",
                      output, output)

    def testInet6Mixed(self):
        self.naming.GetNetAddr.side_effect = [
            [nacaddr.IP('2001:4860:4860::8844')],
            [nacaddr.IP('8.8.4.4'), nacaddr.IP('8.8.8.8'),
             nacaddr.IP('2001:4860:4860::8844'),
             nacaddr.IP('2001:4860:4860::8888')]
        ]
        atp = arista_tp.AristaTrafficPolicy(
            policy.ParsePolicy(GOOD_HEADER + INET6_MIXED, self.naming), EXP_INFO
        )
        output = str(atp)
        self.assertIn("match INET6_MIXED_v6 ipv6", output, output)
        self.assertIn("source prefix 2001:4860:4860::8844/128",
                      output, output)
        self.assertIn("destination prefix 2001:4860:4860::8844/128",
                      output, output)

    def testMixedMixed(self):
        self.naming.GetNetAddr.side_effect = [
            [nacaddr.IP('8.8.4.4'), nacaddr.IP('8.8.8.8'),
             nacaddr.IP('2001:4860:4860::8844'),
             nacaddr.IP('2001:4860:4860::8888')],
            [nacaddr.IP('4.4.2.2'), nacaddr.IP('4.4.4.4'),
             nacaddr.IP('2001:4860:1337::8844'),
             nacaddr.IP('2001:4860:1337::8888')]
        ]
        atp = arista_tp.AristaTrafficPolicy(
            policy.ParsePolicy(GOOD_HEADER + MIXED_MIXED, self.naming), EXP_INFO
        )
        output = str(atp)
        self.assertIn("match MIXED_MIXED ipv4", output, output)
        self.assertIn("source prefix 8.8.4.4/32",
                      output, output)
        self.assertIn("destination prefix 4.4.2.2",
                      output, output)

        self.assertIn("match MIXED_MIXED_v6 ipv6", output, output)
        self.assertIn("source prefix 2001:4860:4860::8844/128",
                      output, output)
        self.assertIn("destination prefix 2001:4860:1337::8844/128",
                      output, output)

    def testMixedAny(self):
        self.naming.GetNetAddr.side_effect = [
            [nacaddr.IP('8.8.4.4'), nacaddr.IP('8.8.8.8'),
             nacaddr.IP('2001:4860:4860::8844'),
             nacaddr.IP('2001:4860:4860::8888')]
        ]
        atp = arista_tp.AristaTrafficPolicy(
            policy.ParsePolicy(GOOD_HEADER + MIXED_ANY, self.naming), EXP_INFO
        )
        output = str(atp)
        self.assertIn("match MIXED_ANY ipv4", output, output)
        self.assertIn("source prefix 8.8.4.4/32",
                      output, output)

        self.assertIn("match MIXED_ANY_v6 ipv6", output, output)
        self.assertIn("source prefix 2001:4860:4860::8844/128",
                      output, output)

    def testAnyMixed(self):
        self.naming.GetNetAddr.side_effect = [
            [nacaddr.IP('8.8.4.4'), nacaddr.IP('8.8.8.8'),
             nacaddr.IP('2001:4860:4860::8844'),
             nacaddr.IP('2001:4860:4860::8888')]
        ]
        atp = arista_tp.AristaTrafficPolicy(
            policy.ParsePolicy(GOOD_HEADER + ANY_MIXED, self.naming), EXP_INFO
        )
        output = str(atp)
        self.assertIn("match ANY_MIXED ipv4", output, output)
        self.assertIn("destination prefix 8.8.4.4/32",
                      output, output)

        self.assertIn("match ANY_MIXED_v6 ipv6", output, output)
        self.assertIn("destination prefix 2001:4860:4860::8844/128",
                      output, output)

    def testInetInet(self):
        self.naming.GetNetAddr.side_effect = [
            [nacaddr.IP('8.8.4.4'), nacaddr.IP('8.8.8.8')],
            [nacaddr.IP('4.4.2.2'), nacaddr.IP('4.4.4.4')],
        ]
        atp = arista_tp.AristaTrafficPolicy(
            policy.ParsePolicy(GOOD_HEADER + INET_INET, self.naming), EXP_INFO
        )
        output = str(atp)
        self.assertIn("match INET_INET ipv4", output, output)
        self.assertIn("source prefix 8.8.4.4/32",
                      output, output)
        self.assertIn("destination prefix 4.4.2.2/32",
                      output, output)

    def testInet6Inet6(self):
        self.naming.GetNetAddr.side_effect = [
            [nacaddr.IP('2001:4860:4860::8844'),
             nacaddr.IP('2001:4860:4860::8888')],
            [nacaddr.IP('2001:4860:1337::8844'),
             nacaddr.IP('2001:4860:1337::8888')]
        ]
        atp = arista_tp.AristaTrafficPolicy(
            policy.ParsePolicy(GOOD_HEADER + INET6_INET6, self.naming), EXP_INFO
        )
        output = str(atp)
        self.assertIn("match INET6_INET6_v6 ipv6", output, output)
        self.assertIn("source prefix 2001:4860:4860::8844/128",
                      output, output)
        self.assertIn("destination prefix 2001:4860:1337::8844/128",
                      output, output)

    def testConfigHelper(self):
        MATCH_INDENT = ' ' * 6
        config = arista_tp.Config()
        config.Append(MATCH_INDENT, 'test')
        config.Append(MATCH_INDENT, 'blah')
        config.Append(MATCH_INDENT, 'foo')
        config.Append(MATCH_INDENT, 'bar')
        config.Append(MATCH_INDENT, 'Mr. T Pities the fool!', verbatim=True)
        self.assertMultiLineEqual(str(config),
                                  '      test\n'
                                  '      blah\n'
                                  '      foo\n'
                                  '      bar\n'
                                  'Mr. T Pities the fool!')

    def testFragmentOffset(self):
        policy_text = GOOD_HEADER + FRAGOFFSET_TERM
        atp = arista_tp.AristaTrafficPolicy(
            policy.ParsePolicy(policy_text, self.naming), EXP_INFO
        )
        output = str(atp)
        self.assertIn("fragment offset 1-7", output, output)

    def testTTL(self):
        atp = arista_tp.AristaTrafficPolicy(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_21, self.naming), EXP_INFO
        )
        output = str(atp)
        self.assertIn("ttl 10", output)

    def testBuildTokens(self):
        self.naming.GetNetAddr.return_value = [nacaddr.IP("10.1.1.1/26", strict=False)]

        atp = arista_tp.AristaTrafficPolicy(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_28, self.naming), EXP_INFO
        )
        st, sst = atp._BuildTokens()
        # print(ppr.pprint(st))
        # print(ppr.pprint(SUPPORTED_TOKENS))
        self.assertEqual(st, SUPPORTED_TOKENS)
        self.assertEqual(sst, SUPPORTED_SUB_TOKENS)

    def testBuildWarningTokens(self):
        atp = arista_tp.AristaTrafficPolicy(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_28, self.naming), EXP_INFO
        )
        st, sst = atp._BuildTokens()
        self.assertEqual(st, SUPPORTED_TOKENS)
        self.assertEqual(sst, SUPPORTED_SUB_TOKENS)

    def testHopOptProtocol(self):
        atp = arista_tp.AristaTrafficPolicy(
            policy.ParsePolicy(GOOD_HEADER + HOPOPT_TERM, self.naming), EXP_INFO
        )
        output = str(atp)
        self.assertIn("protocol 0", output, output)

    def testFailIsFragmentInV6(self):
        self.naming.GetServiceByProto.return_value = ["22"]
        pol = policy.ParsePolicy(GOOD_HEADER_INET6 + OPTION_TERM_1, self.naming)

        self.assertRaises(
            arista_tp.AristaTpFragmentInV6Error,
            arista_tp.AristaTrafficPolicy,
            pol,
            EXP_INFO,
        )


if __name__ == "__main__":
    unittest.main()
