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
from stoq.exceptions import StoqPluginException
from stoq import Payload, RequestMeta, WorkerResponse


class MetadefenderPlugin(WorkerPlugin):
    def __init__(self, config: ConfigParser, plugin_opts: Optional[Dict]) -> None:
        super().__init__(config, plugin_opts)

        self.sandbox_url = None
        self.apikey = None
        self.delay = 30
        self.max_attempts = 10
        self.useragent = 'Falcon Sandbox'
        # Available environments ID:
        #     300: 'Linux (Ubuntu 16.04, 64 bit)',
        #     200: 'Android Static Analysis’,
        #     160: 'Windows 10 64 bit’,
        #     110: 'Windows 7 64 bit’,
        #     100: ‘Windows 7 32 bit’
        self.environment_id = 160
        self.wait_for_results = True

        if plugin_opts and 'sandbox_url' in plugin_opts:
            self.sandbox_url = plugin_opts['sandbox_url']
        elif config.has_option('options', 'sandbox_url'):
            self.sandbox_url = config.get('options', 'sandbox_url')

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
            self.max_attempts = config.getint('options', 'max_attempts')

        if plugin_opts and 'useragent' in plugin_opts:
            self.useragent = plugin_opts['useragent']
        elif config.has_option('options', 'useragent'):
            self.useragent = config.get('options', 'useragent')

        if plugin_opts and 'environment_id' in plugin_opts:
            self.environment_id = int(plugin_opts['environment_id'])
        elif config.has_option('options', 'environment_id'):
            self.environment_id = config.getint('options', 'environment_id')

        if plugin_opts and 'wait_for_results' in plugin_opts:
            self.wait_for_results = plugin_opts['wait_for_results']
        elif config.has_option('options', 'wait_for_results'):
            self.wait_for_results = config.getboolean('options', 'wait_for_results')

        if not self.sandbox_url:
            raise StoqPluginException("Falcon Sandbox URL was not provided")

        if not self.apikey:
            raise StoqPluginException("Falcon Sandbox API Key was not provided")

    def scan(self, payload: Payload, request_meta: RequestMeta) -> WorkerResponse:
        """
        Scan payloads using Falcon Sandbox

        """

        errors = None
        url = f'{self.sandbox_url}/submit/file'
        headers = {'api-key': self.apikey, 'user-agent': self.useragent}
        files = {'file': payload.content}
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
        err = None
        sleep(self.delay)
        while count < self.max_attempts:
            try:
                url = f'{self.sandbox_url}/report/{job_id}/summary'
                headers = {'api-key': self.apikey, 'user-agent': self.useragent}
                response = requests.get(url, headers=headers)
                response.raise_for_status()
                result = response.json()
                if result['state'] not in ('IN_QUEUE', 'IN_PROGRESS'):
                    return result, None
                sleep(self.delay)
            except (JSONDecodeError, KeyError) as err:
                err = str(err)
                sleep(self.delay)
            finally:
                count += 1
                if count >= self.max_attempts:
                    err = f'Scan did not complete in time -- attempts: {count}'
        return None, [err]
