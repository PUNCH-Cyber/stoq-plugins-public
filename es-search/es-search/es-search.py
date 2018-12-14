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
from configparser import ConfigParser
from elasticsearch import Elasticsearch

from stoq.plugins import ConnectorPlugin
from stoq.data_classes import StoqResponse


class ElasticSearchPlugin(ConnectorPlugin):
    def __init__(self, config: ConfigParser, plugin_opts: Optional[Dict]) -> None:
        super().__init__(config, plugin_opts)

        self.es_index = 'stoq'
        self.es_host = None
        self.es_options = None
        self.es_timeout = 60
        self.es_max_retries = 10
        self.index_by_month = True
        self.es = None

        if plugin_opts and 'es_host' in plugin_opts:
            self.es_host = plugin_opts['es_host']
        elif config.has_option('options', 'es_host'):
            self.es_host = config.get('options', 'es_host')

        if plugin_opts and 'es_options' in plugin_opts:
            self.es_options = plugin_opts['es_options']
        elif config.has_option('options', 'es_options'):
            self.es_options = json.loads(config.get('options', 'es_options'))

        if plugin_opts and 'es_timeout' in plugin_opts:
            self.es_timeout = int(plugin_opts['es_timeout'])
        elif config.has_option('options', 'es_timeout'):
            self.es_timeout = int(config.get('options', 'es_timeout'))

        if plugin_opts and 'es_retry' in plugin_opts:
            self.es_retry = plugin_opts['es_retry']
        elif config.has_option('options', 'es_retry'):
            self.es_retry = config.getboolean('options', 'es_retry')

        if plugin_opts and 'es_max_retries' in plugin_opts:
            self.es_max_retries = int(plugin_opts['es_max_retries'])
        elif config.has_option('options', 'es_max_retries'):
            self.es_max_retries = int(config.get('options', 'es_max_retries'))

        if plugin_opts and 'es_index' in plugin_opts:
            self.es_index = plugin_opts['es_index']
        elif config.has_option('options', 'es_index'):
            self.es_index = config.get('options', 'es_index')

        if plugin_opts and 'index_by_month' in plugin_opts:
            self.index_by_month = plugin_opts['index_by_month']
        elif config.has_option('options', 'index_by_month'):
            self.index_by_month = config.getboolean('options', 'index_by_month')

    def save(self, response: StoqResponse) -> None:
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
