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

Query TotalHash API for analysis results

"""

import hmac
import hashlib
import argparse
import xmltodict

from requests.exceptions import HTTPError

from stoq.args import StoqArgs
from stoq.plugins import StoqWorkerPlugin


class TotalHashScan(StoqWorkerPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):
        self.stoq = stoq

        parser = argparse.ArgumentParser()
        parser = StoqArgs(parser)

        worker_opts = parser.add_argument_group("Plugin Options")
        worker_opts.add_argument("-a", "--apikey",
                                 dest='apikey',
                                 help="TotalHash API Key")
        worker_opts.add_argument("-s", "--sha1",
                                 dest='analysis_hash',
                                 default=False,
                                 help="Retrieve analysis from TotalHash for a SHA1 hash")

        options = parser.parse_args(self.stoq.argv[2:])

        super().activate(options=options)

        return True

    def scan(self, payload, **kwargs):
        """
        Query the TotalHash API

        :param None payload: Unused
        :param **kwargs analysis: Query for an analysis of the value provided
        :param **kwargs search: Search for value provided

        :returns: Results from scan
        :rtype: dict or None

        """
        results = None
        query_type = None
        query = None

        if 'analysis' in kwargs:
            query_type = "analysis"
            query = kwargs[query_type]
        elif 'search' in kwargs:
            query_type = "search"
            query = kwargs[query_type]
        elif self.analysis_hash:
            query_type = "analysis"
            query = self.analysis_hash
        elif 'sha1' in kwargs:
            query_type = "analysis"
            query = kwargs['sha1']

        if query_type:
            results = self.query(query_type, query)

        super().scan()

        return results

    def query(self, query_type, value):
        sig = self.generate_signature(value)

        url = "{}/{}/{}&id={}&sign={}".format(self.url, query_type, value,
                                              self.username, sig)

        try:
            response = self.stoq.get_file(url, verify=False)
        except HTTPError:
            return {'result': 0}

        results = xmltodict.parse(response)

        try:
            results['query'] = value
            return results
        except TypeError:
            return None

    def generate_signature(self, value):
        return hmac.new(self.apikey.encode(), value.encode(), hashlib.sha256).hexdigest()
