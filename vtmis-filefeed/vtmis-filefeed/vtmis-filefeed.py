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

Process VTMIS File Feed

"""

import json
import tarfile
import requests
from io import BytesIO
from asyncio import Queue
from datetime import datetime, timedelta
from typing import Dict, List, Union, Optional

from stoq.helpers import StoqConfigParser
from stoq.exceptions import StoqPluginException
from stoq.plugins import ProviderPlugin, WorkerPlugin
from stoq import Payload, ExtractedPayload, Request, WorkerResponse


class VTMISFileFeedPlugin(ProviderPlugin, WorkerPlugin):
    API_URL = 'https://www.virustotal.com/vtapi/v2/file/feed'

    def __init__(self, config: StoqConfigParser) -> None:
        super().__init__(config)

        self.apikey = config.get('options', 'apikey', fallback=None)
        self.time_since = config.get('options', 'time_since', fallback='1m')
        self.download = config.getboolean('options', 'download', fallback=False)

        if not self.apikey:
            raise StoqPluginException("VTMIS API Key does not exist")

    async def ingest(self, queue: Queue) -> None:
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

    async def scan(self, payload: Payload, request: Request) -> WorkerResponse:
        """
        Return individual result from vtmis-filefeed provider

        """
        extracted: List[ExtractedPayload] = []
        errors: List[str] = []
        results: Dict = json.loads(payload.content)
        if self.download:
            self.log.info(f'Downloading VTMIS sample sha1: {results["sha1"]}')
            try:
                response = requests.get(results['link'])
                response.raise_for_status()
                extracted = [ExtractedPayload(response.content)]
            except Exception as err:
                errors.append(f'Unable to download sample {results["sha1"]}: {err}')
        return WorkerResponse(results=results, errors=errors, extracted=extracted)
