#!/usr/bin/env python3

#   Copyright 2014-2019 PUNCH Cyber Analytics Group
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

Process VTMIS File Feed

"""

import json
import tarfile
import requests
from io import BytesIO
from queue import Queue
from typing import Dict, Optional
from configparser import ConfigParser
from datetime import datetime, timedelta

from stoq.exceptions import StoqPluginException
from stoq.plugins import ProviderPlugin, WorkerPlugin
from stoq import (
    Payload,
    RequestMeta,
    WorkerResponse,
)


class VTMISFileFeedPlugin(ProviderPlugin, WorkerPlugin):
    API_URL = 'https://www.virustotal.com/vtapi/v2/file/feed'

    def __init__(self, config: ConfigParser, plugin_opts: Optional[Dict]) -> None:
        super().__init__(config, plugin_opts)

        self.apikey = None
        self.time_slice = '1m'

        if plugin_opts and 'apikey' in plugin_opts:
            self.apikey = plugin_opts['apikey']
        elif config.has_option('options', 'apikey'):
            self.apikey = config.get('options', 'apikey')

        if plugin_opts and 'time_since' in plugin_opts:
            self.time_since = plugin_opts['time_since']
        elif config.has_option('options', 'time_since'):
            self.time_since = config.get('options', 'time_since')

        if not self.apikey:
            raise StoqPluginException("VTMIS API Key does not exist")

    def ingest(self, queue: Queue) -> None:
        for time_slice in self._generate_dates(self.time_since):
            params = {'apikey': self.apikey, 'package': time_slice}
            response = requests.get(self.API_URL, params=params)
            for line in self._decompress(response.content):
                queue.put(Payload(line))

    def _decompress(self, content):
        tar = tarfile.open(fileobj=BytesIO(content), mode='r:bz2')
        for member in tar.getmembers():
            data = tar.extractfile(member.name).read()
            for line in data.splitlines():
                yield line

    def _generate_dates(self, time_since):
        """
        Generate dates that are valid for VTMIS feeds.

        """
        current_time = datetime.now()
        if time_since.endswith("h"):
            max_time = int(time_since[:-1]) + 1
            for i in range(1, max_time):
                delta = current_time - timedelta(hours=i)
                yield delta.strftime("%Y%m%dT%H")
        elif time_since.endswith("m"):
            # VT recommends pulling no sooner than 5 minutes to allow for
            # processing on their side. Let's take that into consideration
            # when the user makes a call and automatically add 5 minutes.
            max_time = int(time_since[:-1]) + 5
            for i in range(5, max_time):
                delta = current_time - timedelta(minutes=i)
                yield delta.strftime("%Y%m%dT%H%M")
        else:
            yield time_since

    def scan(self, payload: Payload, request_meta: RequestMeta) -> WorkerResponse:
        """
        Return individual result from vtmis-filefeed provider

        """
        return WorkerResponse(results=json.loads(payload.content))
