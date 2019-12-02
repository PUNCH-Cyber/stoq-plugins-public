#   Copyright 2014-2018 PUNCH Cyber Analytics Group
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

Save results to ElasticSearch

"""
import json
import certifi

from datetime import datetime
from typing import Optional, Dict
from elasticsearch import Elasticsearch

from stoq.plugins import ConnectorPlugin
from stoq.helpers import StoqConfigParser
from stoq.data_classes import StoqResponse


class ElasticSearchPlugin(ConnectorPlugin):
    def __init__(self, config: StoqConfigParser) -> None:
        super().__init__(config)

        self.es = None
        self.es_host = config.get('options', 'es_host', fallback=None)
        self.es_options = json.loads(config.get('options', 'es_options', fallback='{}'))
        self.es_timeout = config.getint('options', 'es_timeout', fallback=60)
        self.es_retry = config.getboolean('options', 'es_retry', fallback=True)
        self.es_max_retries = config.getint('options', 'es_max_retries', fallback=10)
        self.es_index = config.get('options', 'es_index', fallback='stoq')
        self.index_by_month = config.getboolean(
            'options', 'index_by_month', fallback=True
        )

    async def save(self, response: StoqResponse) -> None:
        """
        Save results to ElasticSearch

        """
        self._connect()

        if self.index_by_month:
            now = datetime.now()
            index = f'{self.es_index}-{now:%Y-%m}'
        else:
            index = self.es_index
        self.es.index(index=index, doc_type=self.es_index, body=str(response))

    def _connect(self):
        """
        Connect to an elasticsearch instance

        """
        if not self.es:
            self.es = Elasticsearch(
                self.es_host,
                timeout=self.es_timeout,
                max_retries=self.es_max_retries,
                retry_on_timeout=self.es_retry,
                ca_certs=certifi.where(),
                **self.es_options,
            )
