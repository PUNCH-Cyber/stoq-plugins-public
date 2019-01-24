#!/usr/bin/env python3

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

Search VTMIS for sha1 hash of a payload or from results of `iocextract` plugin

"""

import requests
from configparser import ConfigParser
from typing import Dict, List, Optional

from stoq.helpers import get_sha1
from stoq.exceptions import StoqPluginException
from stoq.plugins import WorkerPlugin, DispatcherPlugin, DeepDispatcherPlugin
from stoq import (
    Payload,
    RequestMeta,
    WorkerResponse,
    DispatcherResponse,
    DeepDispatcherResponse,
)


class VTMISSearchPlugin(WorkerPlugin, DispatcherPlugin, DeepDispatcherPlugin):
    API_URL = 'https://www.virustotal.com/vtapi/v2'
    ENDPOINTS = {
        'ipv4': ('ip', '/ip-address/report', False),
        'url': ('resource', '/url/report', True),
        'domain': ('domain', '/domain/report', False),
        'sha1': ('resource', '/file/report', True),
    }

    def __init__(self, config: ConfigParser, plugin_opts: Optional[Dict]) -> None:
        super().__init__(config, plugin_opts)

        self.apikey = None

        if plugin_opts and 'apikey' in plugin_opts:
            self.apikey = plugin_opts['apikey']
        elif config.has_option('options', 'apikey'):
            self.apikey = config.get('options', 'apikey')

        if not self.apikey:
            raise StoqPluginException("VTMIS API Key does not exist")

    def scan(self, payload: Payload, request_meta: RequestMeta) -> WorkerResponse:
        """
        Search VTMIS for sha1 hash of a payload or from results of `iocextract` plugin

        """
        results: List[Dict] = []
        seen: List[str] = []

        for worker_result in payload.worker_results:
            if 'iocextract' in worker_result:
                for key, iocs in worker_result['iocextract'].items():
                    for ioc in iocs:
                        if key in self.ENDPOINTS and ioc not in seen:
                            response = self._query_api(ioc, key)
                            seen.append(ioc)
                            results.append(response)
        if not results:
            sha1 = get_sha1(payload.content)
            response = self._query_api(sha1, 'sha1')
            results = [response]

        return WorkerResponse(results=results)

    def _query_api(self, query: str, endpoint: str) -> Dict:
        key, endpoint, allinfo = self.ENDPOINTS[endpoint]
        url = f'{self.API_URL}{endpoint}'
        params = {'apikey': self.apikey, key: query}
        if allinfo:
            params['allinfo'] = 1
        response = requests.get(url, params=params)
        return response.json()

    def get_dispatches(
        self, payload: Payload, request_meta: RequestMeta
    ) -> DispatcherResponse:
        """
        Check if `iocextract` plugin has results, if so, dispatch to `vtmis-search` worker

        """
        dr = DispatcherResponse()
        if 'iocextract' in payload.worker_results:
            dr.plugin_names.append('vtmis-search')
        return dr

    def get_deep_dispatches(
        self, payload: Payload, request_meta: RequestMeta
    ) -> DeepDispatcherResponse:
        """
        Check if `iocextract` plugin has results, if so, deep dispatch to `vtmis-search` worker

        """
        deepdr = DeepDispatcherResponse()
        if (
            'iocextract' in payload.worker_results
            and 'vtmis-search' not in payload.worker_results
        ):
            deepdr.plugin_names.append('vtmis-search')
        return deepdr
