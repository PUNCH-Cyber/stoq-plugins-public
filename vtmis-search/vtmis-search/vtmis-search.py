#!/usr/bin/env python3

#   Copyright 2014-present PUNCH Cyber Analytics Group
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
from typing import Dict, List

from stoq.exceptions import StoqPluginException
from stoq.helpers import get_sha1, StoqConfigParser
from stoq.plugins import WorkerPlugin, DispatcherPlugin
from stoq import Payload, Request, WorkerResponse, DispatcherResponse


class VTMISSearchPlugin(WorkerPlugin, DispatcherPlugin):
    API_URL = 'https://www.virustotal.com/vtapi/v2'
    ENDPOINTS = {
        'ipv4': ('ip', '/ip-address/report', False),
        'url': ('resource', '/url/report', True),
        'domain': ('domain', '/domain/report', False),
        'sha1': ('resource', '/file/report', True),
    }

    def __init__(self, config: StoqConfigParser) -> None:
        super().__init__(config)

        self.apikey = config.get('options', 'apikey', fallback=None)
        if not self.apikey:
            raise StoqPluginException("VTMIS API Key does not exist")

    async def scan(self, payload: Payload, request: Request) -> WorkerResponse:
        """
        Search VTMIS for sha1 hash of a payload or from results of `iocextract` plugin

        """
        results: List[Dict] = []
        seen: Set[str] = set()

        if 'iocextract' in payload.results.workers:
            for key, iocs in payload.results.workers['iocextract'].items():
                for ioc in iocs:
                    if key in self.ENDPOINTS and ioc not in seen:
                        response = self._query_api(ioc, key)
                        seen.add(ioc)
                        results.append(response)
        if not results:
            sha1 = get_sha1(payload.content)
            results = self._query_api(sha1, 'sha1')

        return WorkerResponse(results=results)

    async def get_dispatches(
        self, payload: Payload, request: Request
    ) -> DispatcherResponse:
        """
        Check if `iocextract` plugin has results, if so, dispatch to `vtmis-search` worker

        """
        dr = DispatcherResponse()
        if 'iocextract' in payload.results.workers:
            dr.plugin_names.append('vtmis-search')
        return dr

    def _query_api(self, query: str, endpoint: str) -> Dict:
        key, endpoint, allinfo = self.ENDPOINTS[endpoint]
        url = f'{self.API_URL}{endpoint}'
        params = {'apikey': self.apikey, key: query}
        if allinfo:
            params['allinfo'] = 1
        response = requests.get(url, params=params)
        result = response.json()
        if result:
            result['ioc'] = query
        return [result]
