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

import requests
from time import sleep
from json import JSONDecodeError
from configparser import ConfigParser
from typing import Dict, Optional, Union, Tuple

from stoq.helpers import get_sha1
from stoq.plugins import WorkerPlugin
from stoq.exceptions import StoqPluginException
from stoq import Payload, RequestMeta, WorkerResponse


class MetadefenderPlugin(WorkerPlugin):
    def __init__(self, config: ConfigParser, plugin_opts: Optional[Dict]) -> None:
        super().__init__(config, plugin_opts)

        self.opswat_url = None
        self.apikey = None
        self.delay = 30
        self.max_attempts = 10

        if plugin_opts and 'opswat_url' in plugin_opts:
            self.opswat_url = plugin_opts['opswat_url']
        elif config.has_option('options', 'opswat_url'):
            self.opswat_url = config.get('options', 'opswat_url')

        if plugin_opts and 'apikey' in plugin_opts:
            self.apikey = plugin_opts['apikey']
        elif config.has_option('options', 'apikey'):
            self.apikey = config.get('options', 'apikey')

        if plugin_opts and 'delay' in plugin_opts:
            self.delay = int(plugin_opts['delay'])
        elif config.has_option('options', 'delay'):
            self.delay = int(config.get('options', 'delay'))

        if plugin_opts and 'max_attempts' in plugin_opts:
            self.max_attempts = int(plugin_opts['max_attempts'])
        elif config.has_option('options', 'max_attempts'):
            self.max_attempts = int(config.get('options', 'max_attempts'))

        if not self.opswat_url:
            raise StoqPluginException("MetaDefender URL was not provided")

        if not self.apikey:
            raise StoqPluginException("MetaDefender API Key was not provided")

    def scan(self, payload: Payload, request_meta: RequestMeta) -> WorkerResponse:
        """
        Scan payloads using OPSWAT MetaDefender

        """

        headers = {
            'apikey': self.apikey,
            'filename': payload.payload_meta.extra_data.get(
                'filename', get_sha1(payload.content)
            ),
        }
        response = requests.post(self.opswat_url, data=payload.content, headers=headers)
        response.raise_for_status()
        data_id = response.json()['data_id']
        results, errors = self._parse_results(data_id)
        if errors:
            errors = [errors]
        return WorkerResponse(results, errors=errors)

    def _parse_results(
        self, data_id: str
    ) -> Tuple[Union[Dict, None], Union[str, None]]:
        """
        Wait for a scan to complete and then parse the results

        """
        count = 0
        err = None
        sleep(self.delay)
        while count < self.max_attempts:
            try:
                url = f'{self.opswat_url}/{data_id}'
                response = requests.get(url)
                response.raise_for_status()
                result = response.json()
                if result['scan_results']['progress_percentage'] == 100:
                    return result, None
                sleep(self.delay)
            except (JSONDecodeError, KeyError) as err:
                err = str(err)
                sleep(self.delay)
            finally:
                count += 1
                if count >= self.max_attempts:
                    err = f'Scan did not complete in time -- attempts: {count}'
        return None, err
