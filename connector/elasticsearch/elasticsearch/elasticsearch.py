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
import traceback
import certifi

from datetime import datetime
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import TransportError, RequestError
from elasticsearch.helpers import bulk, BulkIndexError

from stoq.plugins import StoqConnectorPlugin


class ElasticSearchConnector(StoqConnectorPlugin):

    def __init__(self):
        self.date_suffix = None
        self.buffer_lock = threading.Lock()
        self.buffer = []

        super().__init__()

    def activate(self, stoq):
        self.stoq = stoq

        super().activate()

        self.es_timeout = int(self.es_timeout)
        self.es_max_retries = int(self.es_max_retries)
        self.bulk_size = int(self.bulk_size)
        self.bulk_interval = int(self.bulk_interval)

        if self.bulk:
            self.last_commit_time = time.time()
            self.wants_heartbeat = True

        self.date_suffixes = {'day': '%Y%m%d',
                              'month': '%Y%m',
                              'year': '%Y'
                              }

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
        count = 0

        while True:
            try:
                bulk(client=self.es, actions=self.buffer)
                break
            except BulkIndexError as err:
                self.log.error("Failed committing to Elasticsearch: {}".format(err))
                break
            except Exception as err:
                # Make sure we don't end up in an infinite loop
                if count > 5:
                    self.log.error("Failed to commit to Elasticsearch: ", exc_info=True)
                    break

                self.log.warn("Error committing to Elasticsearch, trying again: {}".format(err))
                time.sleep(2)
                count += 1

        self.buffer = []
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

        :param str payload: JSON document to be inserted into elasticsearch
        :param str index: Index name to save content to
        :param str date_suffix: Date formated string to append to the index

        :returns: Results of the elasticsearch insert

        """

        # Define the index name, if available. Will default to the plugin name
        index = kwargs.get('index', self.parentname)

        # Override index name if necessary
        if self.es_single_index_bool:
            index = self.es_single_index_name

        doc_type = index

        date_suffix = kwargs.get('date_suffix', self.date_suffix)
        date_format = self.date_suffixes.get(date_suffix, None)

        # Append a date suffix to the index
        if date_format:
            try:
                date = kwargs.get('date', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                formated_date = datetime.strptime(date, '%Y-%m-%d %H:%M:%S').strftime(date_format)
                index = "{}-{}".format(index, formated_date)
            except Exception as err:
                self.log.error("Unable to append date suffix ({}) to index: {}".format(date, err))

        # Make sure json is sanitized (remove '.' and ' ' from keys) so
        # elasticsearch can handle it.
        payload = self.stoq.sanitize_json(payload)

        # Make sure we convert the dict() into a valid json string,
        # otherwise some issues will arise when values containing bytes
        # are saved. Insert our data and return our results from the ES server
        result = self.stoq.dumps(payload, compactly=True)
        if not self.bulk:
            count = 0
            while True:
                try:
                    return self.es.index(index=index, doc_type=doc_type, body=result)
                except RequestError as err:
                    self.log.error("Failed committing to Elasticsearch: {}".format(err))
                    break
                except Exception as err:
                    # Make sure we don't end up in an infinite loop
                    if count > 5:
                        self.log.error("Failed to commit to Elasticsearch: ", exc_info=True)
                        break

                    self.log.warn("Error committing to Elasticsearch, trying again: {}".format(err))
                    time.sleep(2)
                    count += 1
        else:
            action = {"_index": index,
                      "_type": index,
                      "_source": result}

            self.buffer_lock.acquire()
            self.buffer.append(action)
            buf_len = len(self.buffer)
            self.buffer_lock.release()

            return "queued: {}".format(buf_len)

    def connect(self):
        """
        Connect to an elasticsearch instance

        """
        self.es = Elasticsearch(self.connect_host_list,
                                timeout=self.es_timeout,
                                max_retries=self.es_max_retries,
                                retry_on_timeout=self.es_retry,
                                ca_certs=certifi.where(),
                                **self.connect_opts_dict
                                )
