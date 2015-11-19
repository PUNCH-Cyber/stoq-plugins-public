#   Copyright 2014-2015 PUNCH Cyber Analytics Group
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

Interact with ThreatCrowd API

"""

import sys
import argparse

from stoq.args import StoqArgs
from stoq.plugins import StoqWorkerPlugin


class ThreatCrowdScan(StoqWorkerPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):
        self.stoq = stoq

        parser = argparse.ArgumentParser()
        parser = StoqArgs(parser)

        worker_opts = parser.add_argument_group("Plugin Options")
        worker_opts.add_argument("-q", "--query",
                                 dest='query',
                                 default=False,
                                 help="String to query for")
        worker_opts.add_argument("-e", "--endpoint",
                                 dest='endpoint',
                                 default=False,
                                 help="Endpoint to query: domain, email, ip, or antivirus")

        options = parser.parse_args(sys.argv[2:])
        super().activate(options=options)

        return True

    def scan(self, payload, **kwargs):
        """
        Query the ThreatCrowd API

        :param None payload: Unused
        :param **kwargs endpoint: Endpoint to query against. Valid Options are:
                                  domain, email, ip, or antivirus
        :param **kwargs query: Item to query for

        :returns: Results from scan
        :rtype: dict or None

        """

        if self.query and self.endpoint:
            endpoint = self.endpoint.lower()
            query = self.query
        elif all(key in kwargs for key in ('endpoint', 'query')):
            endpoint = kwargs['endpoint'].lower()
            query = kwargs['query']
        else:
            self.stoq.log.warn("Invalid API parameters: {}".format(kwargs))
            return None

        results = self.api_call(endpoint, query)

        super().scan()

        return results 

    def api_call(self, endpoint, query):
        url = "{}/{}/report/".format(self.url, endpoint)
        params = {endpoint: query}
        response = self.stoq.get_file(url, params=params)
        return self.stoq.loads(response)

