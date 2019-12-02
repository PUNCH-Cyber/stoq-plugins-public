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

Upload content to a Tika server for automated text extraction

"""

import requests

from stoq.plugins import WorkerPlugin
from stoq.helpers import StoqConfigParser
from stoq import Payload, Request, WorkerResponse, ExtractedPayload


class TikaPlugin(WorkerPlugin):
    def __init__(self, config: StoqConfigParser) -> None:
        super().__init__(config)

        self.tika_url = config.get(
            'options', 'tika_url', fallback='http://localhost:9998/tika'
        )

    async def scan(self, payload: Payload, request: Request) -> WorkerResponse:
        """
        Upload content to a Tika server for automated text extraction

        """
        response = requests.put(self.tika_url, data=payload.content)
        response.raise_for_status()
        extracted = [ExtractedPayload(response.content)]
        return WorkerResponse(extracted=extracted)
