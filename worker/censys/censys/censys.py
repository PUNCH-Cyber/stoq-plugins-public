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

Interact with Censys.io API

Examples
========

Basic examples from censys.io API documentation at https://www.censys.io/api

Search:
    stoq-cli.py censys -q "80.http.get.headers.server: Apache" -f "ip,location.country,autonomous_system.asn"-i websites -e search

View:
    stoq-cli.py censys -q google.com -i websites -e search

Report:
    stoq-cli.py censys -q "80.http.get.headers.server: Apache" -f "location.country_code" -i ipv4 -e report

Data:
    stoq-cli.py censys -e data

"""

import argparse

from stoq.args import StoqArgs
from stoq.plugins import StoqWorkerPlugin


class CensysScan(StoqWorkerPlugin):

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
                                 help="Endpoint to query: search, view, report, or data")
        worker_opts.add_argument("-i", "--index",
                                 dest='index',
                                 default=False,
                                 help="Index to query: ipv4, websites, or certificates")
        worker_opts.add_argument("-f", "--field",
                                 dest='field',
                                 default=False,
                                 help="Field(s) for query in dot notation (i.e., location.country_code)")

        options = parser.parse_args(self.stoq.argv[2:])

        super().activate(options=options)

        return True

    def scan(self, payload=None, **kwargs):
        """
        Interact with Censys API

        :param None payload: Unused
        :param **kwargs index: Censys index to be queries. Valid options are:
                               ipv4, websites, or certificates
        :param **kwargs endpoint: Endpoint to query. Valid options are:
                                  search, view, report, or data
        :param **kwargs query: Value to query for
        :param **kwargs field: Field(s) for query in dot notation
                               (i.e., location.country_code)

        :returns: Results returned from Censys API
        :rtype: dict

        """
        results = None
        query = None
        endpoint = None
        index = None
        field = None

        if self.index:
            index = self.index
        elif 'index' in kwargs:
            index = kwargs['index']

        if self.endpoint:
            endpoint = self.endpoint
        elif 'endpoint' in kwargs:
            endpoint = kwargs['endpoint']

        if self.query:
            query = self.query
        elif 'query' in kwargs:
            query = kwargs['query']

        if self.field:
            field = self.field
        elif 'field' in kwargs:
            field = kwargs['field']

        if query:
            if endpoint == "search":
                results = self.search_call(index, query, field)
            elif endpoint == "view":
                results = self.view_call(index, query)
            elif endpoint == "report" and field:
                results = self.report_call(index, query, field)
        elif endpoint == "data":
            results = self.data_call(index)

        super().scan()
        return results 

    def search_call(self, index, query, field):
        if field:
            field = field.split(",")
            query = self.stoq.dumps({"query": query,
                                     "fields": field})
        else:
            query = self.stoq.dumps({"query": query})

        url = "{}/search/{}".format(self.url, index)
        auth = (self.uid, self.secret)
        response = self.stoq.post_file(url, data=query, auth=auth)
        return self.stoq.loads(response)

    def view_call(self, index, query):
        url = "{}/view/{}/{}".format(self.url, index, query)
        auth = (self.uid, self.secret)
        response = self.stoq.get_file(url, auth=auth)
        return self.stoq.loads(response)

    def report_call(self, index, query, field):
        url = "{}/report/{}".format(self.url, index)
        query = self.stoq.dumps({"query": query,
                                 "field": field})
        auth = (self.uid, self.secret)
        response = self.stoq.post_file(url, data=query, auth=auth)
        return self.stoq.loads(response)

    def data_call(self, index):
        url = "{}/data".format(self.url)
        auth = (self.uid, self.secret)
        response = self.stoq.get_file(url, auth=auth)
        return self.stoq.loads(response)

