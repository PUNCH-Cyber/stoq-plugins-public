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

Scan payloads using OPSWAT MetaDefender

"""

import aiohttp

from asyncio import sleep
from json import JSONDecodeError
from typing import Dict, List, Optional, Union, Tuple

from stoq.plugins import WorkerPlugin
from stoq.exceptions import StoqPluginException
from stoq.helpers import get_sha1, StoqConfigParser
from stoq import Error, Payload, Request, WorkerResponse


class MetadefenderPlugin(WorkerPlugin):
    def __init__(self, config: StoqConfigParser) -> None:
        super().__init__(config)

        self.opswat_url = config.get('options', 'opswat_url', fallback=None)
        if not self.opswat_url:
            raise StoqPluginException('MetaDefender URL was not provided')
        self.apikey = config.get('options', 'apikey', fallback=None)
        if not self.apikey:
            raise StoqPluginException('MetaDefender API Key was not provided')
        self.delay = config.getint('options', 'delay', fallback=10)
        self.max_attempts = config.getint('options', 'max_attempts', fallback=10)

    async def scan(self, payload: Payload, request: Request) -> WorkerResponse:
        """
        Scan payloads using OPSWAT MetaDefender

        """

        errors: List[Error] = []
        headers = {
            'apikey': self.apikey,
            'content-type': 'application/octet-stream',
            'filename': payload.results.payload_meta.extra_data.get(
                'filename', get_sha1(payload.content)
            ),
        }
        async with aiohttp.ClientSession(raise_for_status=True) as session:
            async with session.post(self.opswat_url, data=payload.content, headers=headers) as response:
                data_id = response.json()['data_id']
        results, error = await self._parse_results(data_id)
        if error:
            errors.append(
                Error(
                    error=error,
                    plugin_name=self.plugin_name,
                    payload_id=payload.results.payload_id,
                )
            )
        return WorkerResponse(results, errors=errors)

    async def _parse_results(
        self, data_id: str
    ) -> Tuple[Union[Dict, None], Union[str, None]]:
        """
        Wait for a scan to complete and then parse the results

        """
        count: int = 0
        error: Optional[str] = None
        await sleep(self.delay)
        while count < self.max_attempts:
            try:
                url = f'{self.opswat_url}/{data_id}'
                headers = {'apikey': self.apikey}
                async with aiohttp.ClientSesion(raise_for_status=True) as session:
                    async with session.get(url, headers=headers) as response:
                        result = response.json()
                if result['scan_results']['progress_percentage'] == 100:
                    return result, None
                await sleep(self.delay)
            except (JSONDecodeError, KeyError) as err:
                error = str(err)
                await sleep(self.delay)
            finally:
                count += 1
                if count >= self.max_attempts:
                    error = f'Scan did not complete in time -- attempts: {count}'
        return None, error
