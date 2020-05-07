#   Copyright 2014-present PUNCH Cyber Analytics Group
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

"""
Overview
========

Extract and normalize Indicators of Compromise (IOC) from payloads

"""

import os
import re
import socket
import requests
from pathlib import Path
from urllib.parse import urlsplit
from configparser import ConfigParser
from typing import Dict, Set, Optional, List
from ipaddress import ip_address, ip_network
from inspect import currentframe, getframeinfo

from stoq.plugins import WorkerPlugin
from stoq.helpers import StoqConfigParser
from stoq import Payload, Request, WorkerResponse


class IOCExtract(WorkerPlugin):
    """
    IOCExtract

    """

    def __init__(self, config: StoqConfigParser) -> None:
        super().__init__(config)

        self.whitelist_file = config.getlist(
            'options', 'whitelist_file', fallback=['whitelist.txt']
        )
        self.iana_url = config.get(
            'options',
            'iana_url',
            fallback='https://data.iana.org/TLD/tlds-alpha-by-domain.txt',
        )
        self.iana_tld_file = config.get(
            'options', 'iana_tld_file', fallback='tlds-alpha-by-domain.txt'
        )
        iana_tlds = self._get_iana_tlds()

        # Helper regexes
        self.helpers: Dict = {}
        self.helpers[
            'dot'
        ] = r"(?:\.|\[\.\]|\<\.\>|\{\.\}|\(\.\)|\<DOT\>|\[DOT\]|\{DOT\}|\(DOT\))"
        self.helpers[
            'at'
        ] = r"(?:@|\[@\]|\<@\>|\{@\}|\(@\)|\<AT\>|\[AT\]|\{AT\}|\(AT\))"
        self.helpers['http'] = r"\b(?:H(?:XX|TT)P|MEOW):\/\/"
        self.helpers['https'] = r"\b(?:H(?:XX|TT)PS|MEOWS):\/\/"
        self.helpers['tld'] = self.helpers['dot'] + r"(?:%s)\b" % iana_tlds
        self.helpers['host'] = r"\b(?:[A-Z0-9\-]+%s){0,4}" % self.helpers['dot']
        self.helpers['domain'] = r"[A-Z0-9\-]{2,50}" + self.helpers['tld']
        self.helpers['fqdn'] = "{0}{1}".format(
            self.helpers['host'], self.helpers['domain']
        )

        # Simple normalizers, post-processing
        # key=regex_name, value=replacement value
        # re.sub(regex_name, replacement)
        self.normalizers = {
            'dot': '.',
            'at': '@',
            'http': 'http://',
            'https': 'https://',
            'tld': lambda m: m.group(0).lower(),
            'domain': lambda m: m.group(0).lower(),
            'fqdn': lambda m: m.group(0).lower(),
        }

        # Data-type regexes
        self.ioctypes: Dict = {}
        self.ioctypes['md5'] = r"\b[A-F0-9]{32}\b"
        self.ioctypes['sha1'] = r"\b[A-F0-9]{40}\b"
        self.ioctypes['sha256'] = r"\b[A-F0-9]{64}\b"
        self.ioctypes['sha512'] = r"\b[A-F0-9]{128}\b"
        self.ioctypes['ipv4'] = (
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)%s){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
            % self.helpers['dot']
        )
        self.ioctypes[
            'ipv6'
        ] = r"(?:(?:(?:\b|::)(?:(?:[\dA-F]{1,4}(?::|::)){1,7})(?:[\dA-F]{1,4}))(?:(?:(?:\.\d{1,3})?){3})(?:::|\b))|(?:[\dA-F]{1,4}::)|(?:::[\dA-F]{1,4}(?:(?:(?:\.\d{1,3})?){3}))"
        self.ioctypes['mac_address'] = r"\b(?i)(?:[0-9A-F]{2}[:-]){5}(?:[0-9A-F]{2})\b"
        self.ioctypes['email'] = "{0}{1}{2}".format(
            r"\b[A-Z0-9\.\_\%\+\-]+", self.helpers['at'], self.helpers['fqdn']
        )
        self.ioctypes['domain'] = self.helpers['fqdn']
        self.ioctypes['url'] = "(?:{0}|{1})(?:{2}|{3}|{4}){5}".format(
            self.helpers['http'],
            self.helpers['https'],
            self.helpers['fqdn'],
            self.ioctypes['ipv4'],
            self.ioctypes['ipv6'],
            r"(?:[\:\/][A-Z0-9\/\:\+\%\.\_\-\=\~\&\\#\?]*){0,1}",
        )

        # Compile regexes for faster repeat usage
        self.compiled_re: Dict = {}
        self.whitelist_patterns: Dict[str, Set] = {}
        for ioc in self.ioctypes:
            self.whitelist_patterns[ioc] = set()
            self.compiled_re[ioc] = re.compile(self.ioctypes[ioc], re.IGNORECASE)

        self._load_whitelist()

    async def scan(self, payload: Payload, request: Request) -> WorkerResponse:

        normalize: bool = True
        ioctype: str = 'all'
        results: Dict = {}

        if ioctype == 'all':
            for ioc in self.compiled_re:
                if self.compiled_re[ioc]:
                    matches = self.compiled_re[ioc].findall(payload.content.decode(errors='replace'))
                    if matches:
                        results[ioc] = list(set(matches))
        elif self.compiled_re[ioctype]:
            matches = self.compiled_re[ioctype].findall(payload.content.decode(errors='replace'))
            if matches:
                results[ioctype] = list(set(matches))

        if 'ipv6' in results:
            results['ipv6'] = [
                address for address in results['ipv6'] if self._validate_ipv6(address)
            ]
            if not results['ipv6']:
                results.pop('ipv6')

        if normalize:
            results = self._normalize(results)

        return WorkerResponse(results)

    def _normalize(self, parsed_results: Dict[str, List[str]]) -> Dict[str, Set]:
        """
        Normalize, e.g., replace '[DOT]' with '.' for return value

        """

        normalized_results: Dict = {}
        for indicator_type in parsed_results:
            normalized_results[indicator_type] = set()
            for indicator in parsed_results[indicator_type]:
                for normalizer in self.normalizers:
                    indicator = re.sub(
                        self.helpers[normalizer],
                        self.normalizers[normalizer],
                        indicator,
                        flags=re.IGNORECASE,
                    )
                if self._check_whitelist(indicator, indicator_type):
                    normalized_results[indicator_type].add(indicator)
            normalized_results[indicator_type] = list(
                normalized_results[indicator_type]
            )

        return normalized_results

    def _validate_ipv6(self, address: str) -> bool:
        """
        Validate whether a result is a valid ipv6 address

        """
        try:
            socket.inet_pton(socket.AF_INET6, address)
            return True
        except socket.error:
            return False

    def _load_whitelist(self):
        for whitelist_file in self.whitelist_file:
            if not os.path.isabs(whitelist_file):
                filename = getframeinfo(currentframe()).filename
                parent = Path(filename).resolve().parent
                whitelist_file = os.path.join(parent, whitelist_file)
            if not os.path.isfile(whitelist_file):
                self.log.warn(
                    "Invalid whitelist file...skipping {}".format(whitelist_file)
                )
                continue

            with open(whitelist_file) as content:
                for line in content.readlines():
                    if line.startswith("#") or len(line) < 3:
                        continue

                    try:
                        indicator_type, pattern = line.split(':', 1)
                    except:
                        self.log.warn("Invalid line in whitelist: {}".format(line))
                        continue

                    try:
                        self.whitelist_patterns[indicator_type].add(pattern.strip())
                    except KeyError:
                        self.log.warn(
                            "Unknown indicator type: {}".format(indicator_type)
                        )

    def _check_whitelist(self, indicator: str, indicator_type: str) -> bool:

        # Set to False so we can use only domain: in the whitelist_file
        is_url = False

        # Define the default netmask for the ip version
        netmasks = {'ipv4': '32', 'ipv6': '128'}

        try:

            if indicator_type == 'url':
                indicator_type = 'domain'
                is_url = True

            for pattern in self.whitelist_patterns[indicator_type]:
                # Extracted IOC is an IPv4/6 address
                if indicator_type in ['ipv4', 'ipv6']:
                    pattern_has_netmask = False
                    indicator_has_netmask = False

                    if len(pattern.split('/')) > 1:
                        pattern_has_netmask = True

                    if len(indicator.split('/')) > 1:
                        indicator_has_netmask = True

                    try:
                        if pattern_has_netmask:
                            pattern_ip = ip_network("{}".format(pattern))
                        else:
                            pattern_ip = ip_network(
                                "{}/{}".format(pattern, netmasks[indicator_type])
                            )

                        # Remove leading zero's from extracted ip addresses.
                        # Required for python <= 3.7
                        # https://bugs.python.org/issue36384
                        indicator = re.sub(r"0+([0-9])", r"\1", indicator)
                        if indicator_has_netmask:
                            indicator_ip = ip_network(indicator)
                        else:
                            indicator_ip = ip_address(indicator)

                        if indicator_ip in pattern_ip:
                            return False
                    except ValueError as err:
                        self.log.warning(err)
                        return False

                elif indicator_type == 'domain':
                    if is_url:
                        indicator_domain = ".{0.netloc}".format(urlsplit(indicator))
                    else:
                        indicator_domain = ".{}".format(indicator)

                    if indicator_domain.endswith(pattern) or indicator == pattern:
                        return False

                elif indicator_type in [
                    'mac_address',
                    'email',
                    'md5',
                    'sha1',
                    'sha256',
                    'sha512',
                ]:
                    if indicator == pattern:
                        return False

        except KeyError:
            self.log.warn("Unknown indicator type: {}".format(indicator_type))
            return False
        except Exception as err:
            self.log.warn("Unable to handle indicator/pattern: {}".format(str(err)))
            return False

        return True

    def _get_iana_tlds(self) -> str:
        if not os.path.isabs(self.iana_tld_file):
            filename = getframeinfo(currentframe()).filename
            parent = Path(filename).resolve().parent
            self.iana_tld_file = os.path.join(parent, self.iana_tld_file)
        if os.path.isfile(self.iana_tld_file):
            with open(self.iana_tld_file) as f:
                iana_content = f.read()
        else:
            self.log.info(
                "Downloading latest IANA TLD file from {}".format(self.iana_url)
            )
            iana_content = requests.get(self.iana_url).content.decode()

        return "|".join(iana_content.splitlines()[1:])
