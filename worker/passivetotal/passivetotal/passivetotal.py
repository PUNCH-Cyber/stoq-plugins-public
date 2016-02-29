#   Copyright 2014-2016 PUNCH Cyber Analytics Group
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

Interact with PassiveTotal API

.. note:: Based on client.py from PassiveTotal's python api libraries.
          at https://github.com/passivetotal/python_api
"""

import argparse

from stoq.args import StoqArgs
from stoq.plugins import StoqWorkerPlugin

from passivetotal.libs.dns import DnsRequest
from passivetotal.libs.ssl import SslRequest
from passivetotal.libs.whois import WhoisRequest
from passivetotal.libs.actions import ActionsClient
from passivetotal.libs.attributes import AttributeRequest
from passivetotal.common.utilities import to_bool
from passivetotal.common.utilities import valid_date


class PassiveTotalWorker(StoqWorkerPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):

        self.stoq = stoq

        parser = argparse.ArgumentParser()
        parser = StoqArgs(parser)

        subs = parser.add_subparsers(dest='query_resource')

        pdns = subs.add_parser('pdns', help="Query passive DNS data")
        pdns.add_argument('--query', '-q',
                          dest='query',
                          default=False,
                          help="Query for a domain, IP address or wildcard")
        pdns.add_argument('--sources',
                          dest='sources',
                          type=str,
                          default=False,
                          nargs='+',
                          help="CSV string of passive DNS sources")
        pdns.add_argument('--end', '-e',
                          dest='end_time',
                          default=False,
                          type=valid_date,
                          help="Filter records up to this end date (YYYY-MM-DD)")
        pdns.add_argument('--start', '-s',
                          dest='start_time',
                          default=False,
                          type=valid_date,
                          help="Filter records from this start date (YYYY-MM-DD)")
        pdns.add_argument('--timeout', '-t',
                          dest='timeout',
                          default=3,
                          help="Timeout to use for passive DNS source queries")
        pdns.add_argument('--unique',
                          dest='unique',
                          action="store_true",
                          default=False,
                          help="Use this to only get back unique resolutons")

        whois = subs.add_parser('whois', help="Query WHOIS data")
        whois.add_argument('--query', '-q',
                           dest='query',
                           default=False,
                           help="Query for a domain or IP address")
        whois.add_argument('--field', '-f',
                           dest='field',
                           type=str,
                           default=False,
                           help="Run a specific query against a WHOIS field")
        whois.add_argument('--compact',
                           dest='compact',
                           action="store_true",
                           default=False,
                           help="Show WHOIS record in a compact way")

        ssl = subs.add_parser('ssl', help="Query SSL certificate data")
        ssl.add_argument('--query', '-q',
                         dest='query',
                         default=False,
                         help="Query for an IP address or SHA-1")
        ssl.add_argument('--field', '-f',
                         dest='field',
                         type=str,
                         default=False,
                         help="Run a specific query against a certificate field")
        ssl.add_argument('--type', '-t',
                         dest='type',
                         choices=['search', 'history'],
                         default=False,
                         help="Perform a plain search or get history")
        ssl.add_argument('--compact', 
                         dest='compact',
                         action="store_true",
                         default=False,
                         help="Show SSL record in a compact way")

        attribute = subs.add_parser('attribute', help="Query host attribute data")
        attribute.add_argument('--query', '-q',
                               dest='query',
                               default=False,
                               help="Query for a domain or IP address")
        attribute.add_argument('--type', '-t',
                               dest='type',
                               default=False,
                               choices=['tracker', 'component'],
                               help="Query tracker data or component data")

        action = subs.add_parser('action', help="Query and input feedback")
        action.add_argument('--query', '-q',
                            dest='query',
                            default=False,
                            help="Domain, IP address, Email, SSL certificate")
        action.add_argument('--metadata',
                            dest='metadata',
                            action="store_true",
                            default=False,
                            help="Get metadata associated with a query")
        action.add_argument('--tags', 
                            dest='tags',
                            type=str, 
                            default=False,
                            help="Tag values to use in conjunction with an action")
        action.add_argument('--add-tags',
                            dest='add_tags',
                            action="store_true",
                            default=False,
                            help="Add tag values")
        action.add_argument('--remove-tags',
                            dest='remove_tags',
                            action="store_true",
                            default=False,
                            help="Remove tag values")
        action.add_argument('--set-tags', 
                            dest='set_tags',
                            action="store_true",
                            default=False,
                            help="Set tag values")
        action.add_argument('--classification',
                            dest='classification',
                            choices=['malicious', 'non-malicious',
                                     'suspicious', 'unknown'],
                            default=False,
                            help="Classification to apply to the query")
        action.add_argument('--monitor',
                            dest='monitor',
                            choices=['true', 'false'],
                            default=False,
                            help="Read or write a monitor value")
        action.add_argument('--sinkhole',
                            dest='sinkhole',
                            choices=['true', 'false'],
                            default=False,
                            help="Read or write a sinkhole value")
        action.add_argument('--dynamic-dns',
                            dest='dynamic_dns',
                            choices=['true', 'false'],
                            default=False,
                            help="Read or write a dynamic DNS value")
        action.add_argument('--ever-compromised',
                            dest='ever_compromised',
                            choices=['true', 'false'],
                            default=False,
                            help="Read or write a compromised value")

        options = parser.parse_args(self.stoq.argv[2:])

        super().activate(options=options)

        return True

    def scan(self, payload, **kwargs):
        """
        Query PassiveTotal for a domain or IP

        :param None payload: Unused
        :param **kwargs query: Value to query

        :returns: Results from PassiveTotal
        :rtype: dict

        """

        results = None

        if not self.query or kwargs.get('query'):
           self.stoq.log.error("No query provided")
           return

        kwargs.setdefault('query', self.query)
        kwargs.setdefault('resource', self.query_resource)

        if kwargs.get('resource') == 'pdns':
            kwargs.setdefault('sources', self.sources)
            kwargs.setdefault('end', self.end_time)
            kwargs.setdefault('start', self.start_time)
            kwargs.setdefault('timeout', self.timeout)
            kwargs.setdefault('unique', self.unique)

            results = self.get_dns(**kwargs)

        elif kwargs.get('resource') == 'ssl':
            kwargs.setdefault('field', self.field)
            kwargs.setdefault('type', self.type)
            kwargs.setdefault('compact', self.compact)

            results = self.get_ssl(**kwargs)

        elif kwargs.get('resource') == 'whois':
            kwargs.setdefault('field', self.field)
            kwargs.setdefault('compact', self.compact)

            results = self.get_whois(**kwargs)

        elif kwargs.get('resource') == 'action':
            kwargs.setdefault('metadata', self.metadata)
            kwargs.setdefault('tags', self.tags)
            kwargs.setdefault('add_tags', self.add_tags)
            kwargs.setdefault('remove_tags', self.remove_tags)
            kwargs.setdefault('set_tags', self.set_tags)
            kwargs.setdefault('classification', self.classification)
            kwargs.setdefault('monitor', self.monitor)
            kwargs.setdefault('sinkhole', self.sinkhole)
            kwargs.setdefault('dynamic_dns', self.dynamic_dns)
            kwargs.setdefault('ever_compromised', self.ever_compromised)

            results = self.get_action(**kwargs)

        elif kwargs.get('resource') == 'attribute':
            kwargs.setdefault('type', self.type)

            results = self.get_attribute(**kwargs)
        else:
            self.stoq.log.warn("No call provided. Unable to continue.")

        super().scan()

        return results

    def _cleanup_params(self, keys, **kwargs):
        return dict((k, v) for k, v in kwargs.items() if v and k in keys)

    def get_dns(self, **kwargs):
        client = DnsRequest(self.username, self.apikey)

        keys = ['query', 'end', 'start', 'timeout', 'sources']

        params = self._cleanup_params(keys, **kwargs)

        if kwargs.get('unique'):
            return client.get_unique_resolutions(**params)
        else:
            return client.get_passive_dns(**params)

    def get_attribute(self, **kwargs):
        client = AttributeRequest(self.username, self.apikey)

        keys = ['query', 'type']

        params = self._cleanup_params(keys, **kwargs)

        if params.get('type') == 'tracker':
            return client.get_host_attribute_trackers(**params)
        else:
            return client.get_host_attribute_components(**params)


    def get_whois(self, **kwargs):
        client = WhoisRequest(self.username, self.apikey)

        keys = ['query', 'compact', 'field']

        params = self._cleanup_params(keys, **kwargs)

        if not params.get('field'):
            return client.get_whois_details(**params)
        else:
            return client.search_whois_by_field(**params)

    def get_ssl(self, **kwargs):
        client = SslRequest(self.username, self.apikey)

        keys = ['query', 'compact', 'field', 'type']

        params = self._cleanup_params(keys, **kwargs)

        if not params.get('type'):
            return client.get_ssl_certificate_details(**params)
        elif params.get('type') == 'history':
            return client.get_ssl_certificate_history(**params)
        elif params.get('type') == 'search' and params.get('field'):
            return client.search_ssl_certificate_by_field(**params)
        else:
            self.stoq.log.error("No SSL field provided.")
            return None

    def get_action(self, **kwargs):
        client = ActionsClient(self.username, self.apikey)

        keys = ['query', 'tags', 'classification', 'monitor', 'sinkhole', 
                'dynamic_dns', 'ever_compromised', 'metadata']

        params = self._cleanup_params(keys, **kwargs)

        res = None

        if params.get('tags'):
            params['tags'] = [tag.strip() for tag in params['tags'].split(',')]

            if kwargs.get('add_tags'):
                res = client.add_tags(**params)
            elif kwargs.get('remove_tags'):
                res = client.remove_tags(**params)
            elif kwargs.get('set_tags'):
                res = client.set_tags(**params)
            else:
                self.stoq.log.error("No tags provided.")

        if params.get('classification'):
            res = client.set_classification_status(**params)

        if params.get('monitor'):
            params['status'] = to_bool(params['monitor'])
            res = client.set_monitor_status(**params)

        if params.get('sinkhole'):
            params['status'] = to_bool(params['sinkhole'])
            res = client.set_sinkhole_status(**params)

        if params.get('dynamic_dns'):
            params['status'] = to_bool(params['dynamic_dns'])
            res = client.set_dynamic_dns_status(**params)

        if params.get('ever_compromised'):
            params['status'] = to_bool(params['ever_compromised'])
            res = client.set_ever_compromised_status(**params)

        if params.get('metadata'):
            res = client.get_metadata(**params)

        return res

