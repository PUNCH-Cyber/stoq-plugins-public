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

Carve portable executable files from a data stream

"""

import re
import pefile
from io import BytesIO
from typing import Dict, Optional

from stoq.plugins import WorkerPlugin
from stoq.helpers import StoqConfigParser
from stoq import Payload, PayloadMeta, ExtractedPayload, Request, WorkerResponse


class PeCarve(WorkerPlugin):
    def __init__(self, config: StoqConfigParser) -> None:
        super().__init__(config)

        self.pe_headers = config.get(
            'options', 'pe_headers', fallback='\x4d\x5a|\x5a\x4d'
        ).encode()

    async def scan(self, payload: Payload, request: Request) -> WorkerResponse:
        """
        Carve PE files from provided payload

        """

        extracted = []
        content = BytesIO(payload.content)
        content.seek(0)

        for start, end in self._carve(content):
            content.seek(start)
            try:
                pe = pefile.PE(data=content.read())
            except:
                continue
            meta = PayloadMeta(extra_data={'offset': start})
            extracted.append(ExtractedPayload(pe.trim(), meta))
            content.seek(0)
            pe.close()

        return WorkerResponse(extracted=extracted)

    def _carve(self, content: BytesIO):
        """
        Generator that returns a list of offsets for a specified value
        within a payload

        """
        for buff in re.finditer(self.pe_headers, content.read(), re.M | re.S):
            yield buff.start(), buff.end()
