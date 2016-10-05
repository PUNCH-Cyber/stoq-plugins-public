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

Interact with DomainIQ API

"""

import argparse

from IPy import IP

from stoq.args import StoqArgs
from stoq.plugins import StoqWorkerPlugin


class DomainIQScan(StoqWorkerPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):
        self.stoq = stoq

        # DomainIQ API calls are not consistent, so let's map them out so the
        # code can be as simple as possible.
        # https://www.domainiq.com/api_docs
        self.api_calls = {'domain_report': {'key': 'domain', 'method': 'get', 'type': False},
                          'email_report': {'key': 'email', 'method': 'get', 'type': False},
                          'registrant_report': {'key': 'name', 'method': 'get', 'type': False},
                          'ip_report': {'key': 'ip', 'method': 'get', 'type': False},
                          'domain_search': {'key': 'keyword', 'method': 'get', 'type': False},
                          'reverse_dns': {'key': 'domain', 'method': 'get', 'type': False},
                          'reverse_ip': {'key': 'data', 'method': 'get', 'type': True},
                          'reverse_mx': {'key': 'data', 'method': 'get', 'type': True},
                          'reverse_analytics': {'key': 'data', 'method': 'get', 'type': 'id'},
                          }

        parser = argparse.ArgumentParser()
        parser = StoqArgs(parser)

        worker_opts = parser.add_argument_group("Plugin Options")
        worker_opts.add_argument("-a", "--apikey",
                                 dest='apikey',
                                 help="DomainIQ API Key")
        worker_opts.add_argument("-r", "--resource",
                                 dest='api_resource',
                                 default=False,
                                 help="DomainIQ API Resource to interact with")
        worker_opts.add_argument("-q", "--query",
                                 dest='query_value',
                                 default=False,
                                 help="Value to query using the specified API resource")
        worker_opts.add_argument("-l", "--list",
                                 dest='list_resources',
                                 default=False,
                                 action='store_true',
                                 help="List all DomainIQ API resources available")

        options = parser.parse_args(self.stoq.argv[2:])

        super().activate(options=options)

        if self.list_resources:
            print("DomainIQ API Resources Available:")
            for key, value in self.api_calls.items():
                print("\t- {}".format(key))
            print("\nUsage: stoq-cli.py domainiq -r domain_report -q google.com")
            print(" OR    stoq-cli.py domainiq -r reverse_ip -q 8.8.8.8")
            exit(0)

        return True

    def scan(self, payload, **kwargs):
        """
        Interact with public and private DomainIQ API

        :param **kwargs resource: DomainIQ API resource to query
        :param **kwargs query: Query DomainIQ for a specific item

        :returns: Results from specified API call
        :type: dict

        """

        super().scan()

        resource = kwargs.get('resource', self.api_resource)
        query = kwargs.get('query', self.query_value)

        if not query or not resource:
            return {'err': 'No resource or query provided'}

        return self.call_api(resource, query, payload)

    def call_api(self, resource, query=None, payload=None):
        # make sense of the API resource provided
        if resource in self.api_calls:
            service = self.api_calls[resource]
        else:
            self.log.warn("Invalid API resource:{}".format(resource))
            return None

        # Start building the parameters of our API call
        params = {'key': self.apikey,
                  'output_mode': 'json',
                  'service': resource}

        # Determine what key is required, if any
        if service['key']:
            if query:
                params[service['key']] = query

        if service['type'] is True:
            params['type'] = self.get_type(query)
        elif service['type']:
            params['type'] = service['type']

        # Determine whether this API call requires a POST or GET, and whether
        # whether we are uploading a file or not.
        if service['method'] == 'get':
            response = self.stoq.get_file(self.api_url, params=params)
        elif service['method'] == 'post':
            response = self.stoq.post_file(self.api_url, params=params)

        try:
            return self.stoq.loads(response)
        except:
            return None

    def get_type(self, query):
        if query.find("-") > 0:
            return "range"
        elif query[-3:-1].find("/") > 0:
            return "subnet"
        else:
            try:
                IP(query)
                return "ip"
            except:
                return "hostname"
