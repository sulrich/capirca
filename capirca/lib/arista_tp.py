# Copyright 2020 Arista Networks. All Rights Reserved.
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
#
""" arista traffic-policy generator."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import datetime

import six
from absl import logging
from capirca.lib import aclgenerator

# from capirca.lib import nacaddr
# from capirca.lib import summarizer
# from six.moves import range

#          1         2         3
# 123456789012345678901234567890123456789
# traffic-policies
#    traffic-policy foo
#      match dos-attaqrs-source-ip ipv4    << TERM_INDENT
#         !! i am a comment, hear me rawr  << MATCH_INDENT
#         source prefix field-set          << MATCH_INDENT
#         !
#         actions
#            counter edge.dos.attaqrs.source.ip.count  << ACTION_INDENT
#            drop
#      !
#
#          1         2         3
# 123456789012345678901234567890123456789
# traffic-policies
#    field-set ipv4 prefix dst-hjjqurby6yftqk6fa3xx4fas << TERM_INDENT
#       0.0.0.0/0                                       << MATCH_INDENT
#       except 34.64.0.0/26
#    !
#    field-set ipv4 prefix dst-hjjqurby6yftqk6fa3xx4fas
#

# various indentation constants - see above
INDENT_STR = " " * 3  # 3 spaces
TERM_INDENT = 2 * INDENT_STR
MATCH_INDENT = 3 * INDENT_STR
ACTION_INDENT = 4 * INDENT_STR


# generic error class
class Error(Exception):
    pass


class AristaTpTermPortProtocolError(Error):
    pass


class TcpEstablishedWithNonTcpError(Error):
    pass


class AristaTpDuplicateTermError(Error):
    pass


class UnsupportedFilterError(Error):
    pass


class PrecedenceError(Error):
    pass


class AristaTpIndentationError(Error):
    pass


class AristaTpNextIpError(Error):
    pass


class AristaTpMultipleTerminatingActionError(Error):
    pass


class AristaTpFragmentInV6Error(Error):
    pass


class Config(object):
    """config allows a configuration to be assembled easily.

    when appending to the configuration object, the element should be indented
    according to the arista traffic-policy style.

    a text representation of the config can be extracted with str().

    attributes:
    indent: The number of leading spaces on the current line.
    lines: the text lines of the configuration.

    """

    def __init__(self):
        self.lines = []
        self.counters = []

    def __str__(self):
        return "\n".join(self.lines)

    def Append(self, line_indent, line, verbatim=False):
        """append one line to the configuration.

        args:
        - line_indent: config specific spaces prepended to the line
        - line: the configuratoin string to append to the config.
        - verbatim: append line without adjusting indentation. Default False.
        """
        if verbatim:
            self.lines.append(line)
            return

        self.lines.append(line_indent + line.strip())


class Term(aclgenerator.Term):
    """an individual AristaTrafficPolicy term.

    mostly useful for the __str__() method.

    attributes:
     term: the term object from the policy.
     term_type: string indicating type of term, inet, inet6 icmp etc.
     noverbose: boolean to disable verbosity.

    """

    _PLATFORM = "arist_tp"
    _DEFAULT_INDENT = 3
    ACTIONS = {
        "accept": "",
        "deny": "drop",
        "reject": "drop",  # TODO(sulrich): we don't support reject, yet.
        "next": "continue",  # TODO(sulrich): we don't support continue, yet.
    }

    # the following lookup table is used to map between the various types of
    # filters the generator can render.  as new differences are
    # encountered, they should be added to this table.  Accessing members
    # of this table looks like:
    #  self._TERM_TYPE('inet').get('saddr') -> 'source-address'
    #
    # it's critical that the members of each filter type be the same, that is
    # to say that if _TERM_TYPE.get('inet').get('foo') returns something,
    # _TERM_TYPE.get('inet6').get('foo') must return the inet6 equivalent.
    _TERM_TYPE = {
        "inet": {
            "addr_fam": "ipv4",
            "addr": "address",
            "saddr": "source prefix",
            "daddr": "destination prefix",
            "protocol": "protocol",
            "tcp-est": "established",
        },
        "inet6": {
            "addr_fam": "ipv6",
            "addr": "address",
            "saddr": "source prefix",
            "daddr": "destination prefix",
            "protocol": "protocol",
            "tcp-est": "established",
        },
    }

    def __init__(self, term, term_type, noverbose):
        super(Term, self).__init__(term)
        self.term = term
        self.term_type = term_type
        self.noverbose = noverbose

        if term_type not in self._TERM_TYPE:
            raise ValueError("unknown filter type: %s" % term_type)

        if "hopopt" in self.term.protocol:
            loc = self.term.protocol.index("hopopt")
            self.term.protocol[loc] = "hop-by-hop"

        # some options need to modify the actions
        self.extra_actions = []

    def __str__(self):

        # verify platform specific terms. skip the whole term if the platform
        # does not match.
        if self.term.platform:
            if self._PLATFORM not in self.term.platform:
                return ""
        if self.term.platform_exclude:
            if self._PLATFORM in self.term.platform_exclude:
                return ""

        config = Config()
        from_str = []

        # don't render icmpv6 protocol terms under inet, or icmp under inet6
        if (self.term_type == "inet6" and "icmp" in self.term.protocol) or (
            self.term_type == "inet" and "icmpv6" in self.term.protocol
        ):
            logging.debug(
                self.NO_AF_LOG_PROTO.substitute(
                    term=self.term.name,
                    proto=", ".join(self.term.protocol),
                    af=self.term_type,
                )
            )
            return ""

        # comment
        # TODO(sulrich): it might be useful to clean up comments a bit more than
        # just rendering these into the term.
        if self.term.owner and not self.noverbose:
            self.term.comment.append("owner: %s" % self.term.owner)
            if self.term.comment and not self.noverbose:
                for comment in self.term.comment:
                    for line in comment.split("\n"):
                        config.Append(MATCH_INDENT, "!! %s" % line)

        # term verbatim output - this will skip over normal term creation
        # code.  warning generated from policy.py if appropriate.
        if self.term.verbatim:
            for next_term in self.term.verbatim:
                if next_term[0] == self._PLATFORM:
                    config.Append(MATCH_INDENT, str(next_term[1]), verbatim=True)
                return str(config)

        # helper for per-address-family keywords.
        family_keywords = self._TERM_TYPE.get(self.term_type)

        # option processing
        print("options:", self.term.option)
        if self.term.option:
            for opt in [str(x) for x in self.term.option]:
                if opt.startswith("sample"):
                    print("unsupported option: sample - %s", self.term.name)
                # only append tcp-established for option established when
                # tcp is the only protocol
                if opt.startswith("established"):
                    if self.term.protocol == ["tcp"]:
                        if "tcp-established;" not in from_str:
                            from_str.append(family_keywords["tcp-est"])

                # if tcp-established specified, but more than just tcp is included
                # in the protocols, raise an error
                elif opt.startswith("tcp-established"):
                    flag = family_keywords["tcp-est"]
                    if self.term.protocol == ["tcp"]:
                        if flag not in from_str:
                            from_str.append(flag)
                    else:
                        raise TcpEstablishedWithNonTcpError(
                            "tcp-established can only be used with tcp protocol in term %s"
                            % self.term.name
                        )
                elif opt.startswith("initial") and "tcp" in self.term.protocol:
                    from_str.append("tcp-initial;")
                elif opt.startswith("first-fragment"):
                    from_str.append("first-fragment;")

                # we don't have a special way of dealing with this, so we output it and
                # hope the user knows what they're doing.
                else:
                    from_str.append("%s" % opt)

        has_match_criteria = (
            self.term.address or self.term.destination_address or
            self.term.destination_port or self.term.destination_prefix or
            self.term.destination_prefix_except or self.term.encapsulate or
            self.term.forwarding_class or self.term.forwarding_class_except or
            self.term.fragment_offset or self.term.hop_limit or
            self.term.next_ip or self.term.port or self.term.protocol or
            self.term.protocol_except or self.term.source_address or
            self.term.source_port or self.term.source_prefix or
            self.term.source_prefix_except or self.term.traffic_type or
            self.term.ttl
        )

        if has_match_criteria:
            config.Append(
                TERM_INDENT,
                "match %s %s" % (self.term.name, family_keywords["addr_fam"]),
            )
            term_af = self.AF_MAP.get(self.term_type)

            # comment - could use a little formatting love
            if self.term.owner and not self.noverbose:
                self.term.comment.append("owner: %s" % self.term.owner)
            if self.term.comment and not self.noverbose:
                for comment in self.term.comment:
                    for line in comment.split("\n"):
                        config.Append(MATCH_INDENT, "!! " + line)

            # address
            address = self.term.GetAddressOfVersion("address", term_af)
            if address:
                config.Append(MATCH_INDENT, "%s {" % family_keywords["addr"])
                for addr in address:
                    config.Append(MATCH_INDENT, "%s" % addr)

            elif self.term.address:
                logging.debug(
                    self.NO_AF_LOG_ADDR.substitute(
                        term=self.term.name, af=self.term_type
                    )
                )
                return ""

            # source address
            src_addr = self.term.GetAddressOfVersion("source_address", term_af)
            src_addr_ex = self.term.GetAddressOfVersion(
                "source_address_exclude", term_af
            )
            print("s a_ex:", src_addr_ex)
            src_addr, src_addr_ex = self._MinimizePrefixes(src_addr, src_addr_ex)

            if src_addr:
                src_str = "source prefix"
                if src_addr_ex:
                    src_str += " src-%s" % self.term.name
                    # we need to put the resulting field-set somewhere
                    # src_fs = self._genPrefixFieldset('dst',
                    #                                   self.term.name,
                    #                                   src_addr,
                    #                                   src_addr_ex,
                    #                                  term_af)
                    # print(src_fs)
                else:
                    for addr in src_addr:
                        src_str += " %s" % addr

                config.Append(MATCH_INDENT, src_str)

            elif self.term.source_address:
                logging.debug(
                    self.NO_AF_LOG_ADDR.substitute(
                        term=self.term.name, direction="source", af=self.term_type
                    )
                )
                return ""

            # destination address
            dst_addr = self.term.GetAddressOfVersion("destination_address", term_af)
            # print(dst_addr)
            dst_addr_ex = self.term.GetAddressOfVersion(
                "destination_address_exclude", term_af
            )
            dst_addr, dst_addr_ex = self._MinimizePrefixes(dst_addr, dst_addr_ex)

            if dst_addr:
                dst_str = "destination prefix"
                if dst_addr_ex:
                    dst_str += " dst-%s" % self.term.name
                    # we need to put the resulting field-set somewhere
                    # dst_fs = self._genPrefixFieldset('dst',
                    #                                   self.term.name,
                    #                                   dst_addr,
                    #                                   dst_addr_ex,
                    #                                   term_af)
                    # print(dst_fs)
                else:
                    for addr in dst_addr:
                        dst_str += " %s" % addr

                config.Append(MATCH_INDENT, dst_str)

            elif self.term.destination_address:
                logging.debug(
                    self.NO_AF_LOG_ADDR.substitute(
                        term=self.term.name, direction="destination", af=self.term_type
                    )
                )
                return ""

            # # forwarding-class
            # if self.term.forwarding_class:
            #     config.Append(MATCH_INDENT, 'forwarding-class %s' %
            #                   self._Group(self.term.forwarding_class, lc=False))

            # source prefix <except> list
            #     self._genPrefixFieldset(dir, name, i_pfxs, e_pfxs, af):
            if self.term.source_prefix or self.term.source_prefix_except:
                src_pfx_str = "source address"
                for pfx in self.term.source_prefix:
                    src_pfx_str += " %s" % pfx
                for epfx in self.term.source_prefix_except:
                    src_pfx_str += " except %s" % pfx

                config.Append(MATCH_INDENT, " %s" % src_pfx_str)

            # destination prefix <except> list
            if self.term.destination_prefix or self.term.destination_prefix_except:
                dst_pfx_str = "destination address"
                for pfx in self.term.destination_prefix:
                    dst_pfx_str += " %s" % pfx
                for epfx in self.term.destination_prefix_except:
                    dst_pfx_str += " except %s" % pfx

                config.Append(MATCH_INDENT, " %s" % dst_pfx_str)

            # protocol
            if self.term.protocol:
                config.Append(
                    MATCH_INDENT,
                    family_keywords["protocol"] + " " + self._Group(self.term.protocol),
                )

            # protocol
            if self.term.protocol_except:
                # same as above
                config.Append(
                    MATCH_INDENT,
                    family_keywords["protocol-except"] + " " +
                    self._Group(self.term.protocol_except))

            # port
            if self.term.port:
                print("port: ", self.term.port)
                config.Append(MATCH_INDENT, "port %s" % self._Group(self.term.port))

            # source port
            if self.term.source_port:
                print("src port:", self.term.source_port)
                config.Append(
                    MATCH_INDENT, "source-port %s" % self._Group(self.term.source_port)
                )

            # destination port
            if self.term.destination_port:
                print("dst port:", self.term.destination_port)
                config.Append(
                    MATCH_INDENT,
                    "destination-port %s" % self._Group(self.term.destination_port),
                )

            # append any options beloging in the from {} section
            for next_str in from_str:
                config.Append(MATCH_INDENT, next_str)

            # packet length
            if self.term.packet_length:
                config.Append(MATCH_INDENT, "ip length %s" % self.term.packet_length)

            # fragment offset
            if self.term.fragment_offset:
                config.Append(
                    MATCH_INDENT, "fragment offset %s" % self.term.fragment_offset
                )

            if self.term.ttl:
                config.Append(MATCH_INDENT, "ttl %s" % self.term.ttl)

            # icmp-types
            icmp_types = [""]
            if self.term.icmp_type:
                icmp_types = self.NormalizeIcmpTypes(
                    self.term.icmp_type, self.term.protocol, self.term_type
                )
            if icmp_types != [""]:
                config.Append(MATCH_INDENT, "icmp-type %s" % self._Group(icmp_types))
            if self.term.icmp_code:
                config.Append(
                    MATCH_INDENT, "icmp-code %s" % self._Group(self.term.icmp_code)
                )

            if self.term.traffic_type:
                config.Append(
                    MATCH_INDENT,
                    "traffic-type %s" % self._Group(self.term.traffic_type),
                )

        # ACTIONS
        # if there's no action, then this is an implicit permit
        self.CheckTerminatingAction()
        print("extra_actions:", self.extra_actions)
        unique_actions = set(self.extra_actions)

        if len(unique_actions) <= 1:
            for action in [
                self.term.logging,
                self.term.counter,
                self.term.dscp_set,
            ]:
                if action:
                    try:
                        unique_actions.update(action)
                    except TypeError:
                        unique_actions.add(action)
                    if len(unique_actions) > 1:
                        break

        if len(unique_actions) == 1:
            current_action = self.ACTIONS.get(unique_actions.pop(), "next_ip")
            print("current_action:", current_action)

            if (
                self.term_type == "inet" and current_action in ["discard", "reject"]
            ) or (self.term_type == "inet6" and current_action in ["reject"]):
                config.Append(MATCH_INDENT, "%s;" % current_action)
            else:
                config.Append(MATCH_INDENT, "actions")
                config.Append(ACTION_INDENT, "%s" % current_action)

        elif len(unique_actions) > 1:
            config.Append(MATCH_INDENT, "actions")
            # logging
            if self.term.logging:
                config.Append(ACTION_INDENT, "log")

            if self.term.counter:
                config.Append(ACTION_INDENT, "counter %s" % self.term.counter)

            if self.term.next_ip:
                self.NextIpCheck(self.term.next_ip, self.term.name)
                if self.term.next_ip[0].version == 4:
                    config.Append(
                        ACTION_INDENT, "next-ip %s;" % str(self.term.next_ip[0])
                    )
                else:
                    config.Append(
                        ACTION_INDENT, "next-ip6 %s;" % str(self.term.next_ip[0])
                    )

            for action in self.extra_actions:
                config.Append(ACTION_INDENT, action)

            # DSCP SET
            if self.term.dscp_set:
                if self.term_type == "inet6":
                    config.Append(
                        ACTION_INDENT, "traffic-class %s;" % self.term.dscp_set
                    )
                else:
                    config.Append(ACTION_INDENT, "dscp %s;" % self.term.dscp_set)

            config.Append(MATCH_INDENT, "!")  # end then{...}
        config.Append(TERM_INDENT, "!")  # end term accept-foo-to-bar { ... }

        return str(config)

    def _Range():
        """generate a valid range for EOS traffic-policies"""
        pass

    def _genPrefixFieldset(dir, name, pfxs, ex_pfxs, af):
        field_list = ""

        for p in pfxs:
            field_list += " %s" % p

        for p in ex_pfxs:
            field_list += " except %s" % p

        fieldset_hdr = (
            TERM_INDENT + "field-set " + af + " prefix " + dir + "-" + ("%s" % name)
        )
        field_set = fieldset_hdr + field_list

        return field_set

    @staticmethod
    def NextIpCheck(next_ip, term_name):
        if len(next_ip) > 1:
            raise AristaTpNextIpError(
                "The following term has more " "than one next IP value: %s" % term_name
            )
        if next_ip[0].num_addresses > 1:
            raise AristaTpNextIpError(
                "The following term has a subnet " "instead of a host: %s" % term_name
            )

    def CheckTerminatingAction(self):
        action = set(self.term.action)
        # the following aren't supported on arista_tp's
        # we should raise an error
        if self.term.encapsulate:
            action.add(self.term.encapsulate)
        if self.term.routing_instance:
            action.add(self.term.routing_instance)
        if len(action) > 1:
            raise AristaTpMultipleTerminatingActionError(
                "term has multiple terminating/unsupported actions: %s" % self.term.name
            )

    def _MinimizePrefixes(self, include, exclude):
        """Calculate a minimal set of prefixes for match conditions.

        Args:
          include: Iterable of nacaddr objects, prefixes to match.
          exclude: Iterable of nacaddr objects, prefixes to exclude.
        Returns:
          A tuple (I,E) where I and E are lists containing the minimized
          versions of include and exclude, respectively.  The order
          of each input list is preserved.
        """
        # Remove any included prefixes that have EXACT matches in the
        # excluded list.  Excluded prefixes take precedence on the router
        # regardless of the order in which the include/exclude are applied.
        exclude_set = set(exclude)
        include_result = [ip for ip in include if ip not in exclude_set]

        # Every address match condition on a AristaTp firewall filter
        # contains an implicit "0/0 except" or "0::0/0 except".  If an
        # excluded prefix is not contained within any less-specific prefix
        # in the included set, we can elide it.  In other words, if the
        # next-less-specific prefix is the implicit "default except",
        # there is no need to configure the more specific "except".
        #
        # TODO(kbrint): this could be made more efficient with a Patricia trie.
        # TODO(sulrich): ask kevin about this
        exclude_result = []
        for exclude_prefix in exclude:
            for include_prefix in include_result:
                if exclude_prefix.subnet_of(include_prefix):
                    exclude_result.append(exclude_prefix)
                    break

        return include_result, exclude_result

    def _Group(self, group, lc=True):
        """If 1 item return it, else return [ item1 item2 ].

        Args:
          group: a list.  could be a list of strings (protocols) or a list of
                 tuples (ports)
          lc: return a lower cased result for text.  Default is True.

        Returns:
          rval: a string surrounded by '[' and '];' if len(group) > 1
                or with just ';' appended if len(group) == 1
        """

        def _FormattedGroup(el, lc=True):
            """Return the actual formatting of an individual element.

            Args:
              el: either a string (protocol) or a tuple (ports)
              lc: return lower cased result for text.  Default is True.

            Returns:
              string: either the lower()'ed string or the ports, hyphenated
                      if they're a range, or by itself if it's not.
            """
            if isinstance(el, str) or isinstance(el, six.text_type):
                if lc:
                    return el
                else:
                    return el.lower()
            elif isinstance(el, int):
                return str(el)
            # type is a tuple below here
            elif el[0] == el[1]:
                return "%d" % el[0]
            else:
                return "%d-%d" % (el[0], el[1])

        if len(group) > 1:
            rval = "[ " + " ".join([_FormattedGroup(x) for x in group]) + " ];"
        else:
            rval = _FormattedGroup(group[0]) + ";"
        return rval


class AristaTrafficPolicy(aclgenerator.ACLGenerator):
    """arista traffic-policy rendering class.

      takes a policy object and renders the output into a syntax
      which is understood by arista switches.

    Attributes:
      pol: policy.Policy object

    """

    _AF_MAP = {"inet": 4, "inet6": 6, "mixed": None}
    _DEFAULT_PROTOCOL = "ip"
    _PLATFORM = "arista_tp"
    _SUPPORTED_AF = set(("inet", "inet6"))
    _TERM = Term

    SUFFIX = ".tpl"

    def _BuildTokens(self):
        """

        returns:
            tuple of supported tokens and sub tokens
        """
        supported_tokens, supported_sub_tokens = super(
            AristaTrafficPolicy, self
        )._BuildTokens()

        supported_tokens |= {
            "address",
            "counter",
            "destination_prefix",
            "destination_prefix_except",
            "dscp_set",
            "forwarding_class",
            "fragment_offset",
            "hop_limit",
            "icmp_code",
            "logging",
            "packet_length",
            "port",
            "protocol_except",
            "source_prefix",
            "source_prefix_except",
            "ttl",
        }
        supported_sub_tokens.update(
            {
                "option": {
                    "established",
                    "is-fragment",
                    ".*",  # make ArbitraryOptions work, yolo.
                    "tcp-established",
                    "tcp-initial",
                }
            }
        )
        return supported_tokens, supported_sub_tokens

    def _TranslatePolicy(self, pol, exp_info):
        self.arista_traffic_policies = []

        current_date = datetime.datetime.utcnow().date()
        exp_info_date = current_date + datetime.timedelta(weeks=exp_info)

        for header, terms in pol.filters:
            if self._PLATFORM not in header.platforms:
                continue

            filter_options = header.FilterOptions(self._PLATFORM)
            filter_name = header.FilterName(self._PLATFORM)
            noverbose = "noverbose" in filter_options[1:]

            # default to ipv4 policies
            filter_type = "inet"
            if len(filter_options) > 1:
                filter_type = filter_options[1]

            term_names = set()
            new_terms = []
            policy_counters = set()  # a set of the counters in the policy
            for term in terms:
                term.name = self.FixTermLength(term.name)

                # TODO(sulrich) this should be updated to check across AFs
                if term.name in term_names:
                    raise AristaTpDuplicateTermError(
                        "multiple terms named: %s" % term.name
                    )

                term_names.add(term.name)

                # generate the unique list of named counters
                if term.counter:
                    policy_counters.add(term.counter)

                term = self.FixHighPorts(term, af=filter_type)
                if not term:
                    continue

                if term.expiration:
                    if term.expiration <= exp_info_date:
                        logging.info(
                            "INFO: term %s in policy %s expires "
                            "in less than two weeks.",
                            term.name,
                            filter_name,
                        )
                    if term.expiration <= current_date:
                        logging.warning(
                            "WARNING: term %s in policy %s is expired and "
                            "will not be rendered.",
                            term.name,
                            filter_name,
                        )
                        continue
                # if 'is-fragment' in term.option and filter_type == 'ipv6':
                #     raise AristaTpFragmentInV6Error(
                #         'the term %s uses "is-fragment" but '
                #         'is a v6 policy.' % term.name)

                new_terms.append(self._TERM(term, filter_type, noverbose))

            self.arista_traffic_policies.append(
                (header, filter_name, filter_type, new_terms, policy_counters)
            )

    def __str__(self):
        config = Config()

        for (
            header,
            filter_name,
            filter_type,
            terms,
            counters,
        ) in self.arista_traffic_policies:
            # add the header information
            config.Append("", "traffic-policies")

            # if there are counters, export the list of counters
            if len(counters) > 0:
                str_counters = ""
                for ctr in counters:
                    str_counters += " %s" % ctr

                config.Append("   ", "counters %s" % str_counters)

            config.Append("   ", "no traffic-policy %s" % filter_name)
            config.Append("   ", "traffic-policy %s" % filter_name)

            for term in terms:
                term_str = str(term)
                if term_str:
                    config.Append("", term_str, verbatim=True)

        return str(config) + "\n"
