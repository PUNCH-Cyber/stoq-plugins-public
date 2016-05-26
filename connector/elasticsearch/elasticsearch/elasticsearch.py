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
import time
import threading
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

from stoq.plugins import StoqConnectorPlugin


class ElasticSearchConnector(StoqConnectorPlugin):

    def __init__(self):
        super().__init__()
        self.buffer_lock = threading.Lock()
        self.buffer = []

    def activate(self, stoq):
        self.stoq = stoq
        super().activate()
        self.bulk_size = int(self.bulk_size)
        self.bulk_interval = int(self.bulk_interval)
        if self.bulk:
            self.last_commit_time = time.time()
            self.wants_heartbeat = True
        # No ES connection, let's make one.
        self.connect()

    def deactivate(self):
        # send one last commit as we shut down, just in case.
        if self.bulk:
            self._commit()
        super().deactivate()

    def query(self, index, query):
        """
        Query elasticsearch

        :param bytes index: Index to search
        :param bytes query: Item to search for in the defined index

        :returns: Search results

        """

        return self.es.search(index, q=query)

    def heartbeat(self):
        while True:
            time.sleep(1)
            self._check_commit()

    def _commit(self):
        self.buffer_lock.acquire()
        bulk(client=self.es, actions=self.buffer)
        while len(self.buffer) > 0:
            self.buffer.pop()
        self.buffer_lock.release()

    def _check_commit(self):
        if not self.bulk:
            return
        else:
            now = time.time()
            self.buffer_lock.acquire()
            buf_len = len(self.buffer)
            self.buffer_lock.release()
            if (now - self.last_commit_time) > self.bulk_interval or buf_len > self.bulk_size:
                self._commit()
                self.last_commit_time = now

    # Primitive elasticsearch connector.
    def save(self, payload, **kwargs):
        """
        Save results to elasticsearch

        :param bytes payload: Content to be inserted into elasticsearch
        :param **kwargs index: Index name to save content to

        :returns: Results of the elasticsearch insert

        """

        # Define the index name, if available. Will default to the plugin name
        index = kwargs.get('index', self.parentname)

        # Make sure we convert the dict() into a valid json string,
        # otherwise some issues will arise when values containing bytes
        # are saved.
        # Insert our data and return our results from the ES server
        if not self.bulk:
            return self.es.index(index=index,
                                 doc_type=index,
                                 body=self.stoq.dumps(payload))
        else:
            action = {"_op_type": "index",
                      "_index": index,
                      "_type": index}
            payload.update(action)
            self.buffer_lock.acquire()
            self.buffer.append(self.stoq.dumps(payload))
            buf_len = len(self.buffer)
            self.buffer_lock.release()
            return "queued: {}".format(buf_len)

    def connect(self):
        """
        Connect to an elasticsearch instance

        """
        self.es = Elasticsearch(self.conn)
