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

Scan payloads using Falcon Sandbox

"""

import requests
from time import sleep
from json import JSONDecodeError
from configparser import ConfigParser
from typing import Dict, Optional, Union, Tuple, List

from stoq.plugins import WorkerPlugin
from stoq.helpers import StoqConfigParser, get_sha1
from stoq.exceptions import StoqPluginException
from stoq import Error, Payload, Request, WorkerResponse


class FalconSandboxPlugin(WorkerPlugin):
    def __init__(self, config: StoqConfigParser) -> None:
        super().__init__(config)

        self.sandbox_url = config.get('options', 'sandbox_url', fallback=None)
        if not self.sandbox_url:
            raise StoqPluginException("Falcon Sandbox URL was not provided")
        self.apikey = config.get('options', 'apikey', fallback=None)
        if not self.apikey:
            raise StoqPluginException("Falcon Sandbox API Key was not provided")
        self.delay = config.getint('options', 'delay', fallback=30)
        self.max_attempts = config.getint('options', 'max_attempts', fallback=10)
        self.useragent = config.get('options', 'useragent', fallback='Falcon Sandbox')
        # Available environments ID:
        #     300: 'Linux (Ubuntu 16.04, 64 bit)',
        #     200: 'Android Static Analysis’,
        #     160: 'Windows 10 64 bit’,
        #     110: 'Windows 7 64 bit’,
        #     100: ‘Windows 7 32 bit’
        self.environment_id = config.getint('options', 'environment_id', fallback=160)
        self.wait_for_results = config.getboolean(
            'options', 'wait_for_results', fallback=True
        )

    async def scan(self, payload: Payload, request: Request) -> WorkerResponse:
        """
        Scan payloads using Falcon Sandbox

        """

        errors: List[Error] = []
        url = f'{self.sandbox_url}/submit/file'
        headers = {'api-key': self.apikey, 'user-agent': self.useragent}
        filename = payload.results.payload_meta.extra_data.get(
            'filename', get_sha1(payload.content)
        )
        if isinstance(filename, bytes):
            filename = filename.decode()
        files = {'file': (filename, payload.content)}
        data = {'environment_id': self.environment_id}
        response = requests.post(url, data=data, files=files, headers=headers)
        response.raise_for_status()
        results = response.json()
        if self.wait_for_results:
            results, errors = self._parse_results(results['job_id'])
        return WorkerResponse(results, errors=errors)

    def _parse_results(
        self, job_id: str
    ) -> Tuple[Union[Dict, None], Union[List[str], None]]:
        """
        Wait for a scan to complete and then parse the results

        """
        count = 0
        errors: List[Error] = []

        while count < self.max_attempts:
            sleep(self.delay)
            try:
                url = f'{self.sandbox_url}/report/{job_id}/summary'
                headers = {'api-key': self.apikey, 'user-agent': self.useragent}
                response = requests.get(url, headers=headers)
                response.raise_for_status()
                result = response.json()
                if result['state'] not in ('IN_QUEUE', 'IN_PROGRESS'):
                    return result, errors
            except (JSONDecodeError, KeyError) as err:
                errors.append(
                    Error(
                        error=err, plugin_name=self.plugin_name, payload_id=payload_id
                    )
                )
            finally:
                count += 1
                if count >= self.max_attempts:
                    msg = f'Scan did not complete in time -- attempts: {count}'
                    errors.append(
                        Error(
                            error=msg,
                            plugin_name=self.plugin_name,
                            payload_id=payload_id,
                        )
                    )
        return None, errors
