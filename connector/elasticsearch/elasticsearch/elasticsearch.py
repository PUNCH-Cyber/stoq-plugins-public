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

Saves content to an ElasticSearch index

"""

from elasticsearch import Elasticsearch

from stoq.plugins import StoqConnectorPlugin


class ElasticSearchConnector(StoqConnectorPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):
        self.stoq = stoq
        super().activate()

    def query(self, index, query):
        """
        Query elasticsearch 

        :param bytes index: Index to search
        :param bytes query: Item to search for in the defined index

        :returns: Search results

        """

        # No ES connection, let's make one.
        try:
            if not self.es:
                self.connect()
        except:
            self.connect()

        return self.es.search(index, q=query)

    # Primative elasticsearch connector.
    def save(self, payload, **kwargs):
        """
        Save results to elasticsearch

        :param bytes payload: Content to be inserted into elasticsearch
        :param **kwargs index: Index name to save content to

        :returns: Results of the elasticsearch insert

        """

        # No ES connection, let's make one.
        try:
            if not self.es:
                self.connect()
        except:
            self.connect()

        # Make sure we convert the dict() into a valid json string,
        # otherwise some issues will arise when values containsing bytes
        # are saved.
        payload = self.stoq.dumps(payload)

        # Define the index name, if available. Will default to the plugin name
        index = kwargs.get('index', self.parentname)

        # Insert our data and return our results from the ES server
        return self.es.index(index=index,
                             doc_type=index,
                             body=payload)

    def connect(self):
        """
        Connect to an elasticsearch instance

        """

        self.es = Elasticsearch(self.conn)
