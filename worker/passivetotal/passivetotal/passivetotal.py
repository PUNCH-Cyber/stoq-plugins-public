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

Query PassiveTotal API for a domain or IP address

"""

import sys
import argparse

from stoq.args import StoqArgs
from stoq.plugins import StoqWorkerPlugin


class PassiveTotalWorker(StoqWorkerPlugin):

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
                                 help="Connector to use for queries")

        options = parser.parse_args(sys.argv[2:])
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

        super().scan()

        # Determine if we are handling a payload or our query parameter was
        # provided at the command line
        if 'query' in kwargs:
            self.query = kwargs['query']

        if not self.query:
            return

        # Define the query URL
        search_url = "{}/passive".format(self.url)

        # Setup the content to be POST'd
        params = {'api_key': self.apikey, 'query': self.query}

        # Submit the query and handle the results
        results = self.stoq.get_file(search_url, params=params)

        # Ensure the content is a dict
        return self.stoq.loads(results)

