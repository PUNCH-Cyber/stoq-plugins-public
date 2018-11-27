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

Carve portable executable files from a data stream

"""

import re
import pefile
from io import BytesIO
from typing import Dict, Optional
from configparser import ConfigParser

from stoq.plugins import WorkerPlugin
from stoq import Payload, PayloadMeta, ExtractedPayload, RequestMeta, WorkerResponse


class PeCarve(WorkerPlugin):
    def __init__(self, config: ConfigParser, plugin_opts: Optional[Dict]) -> None:
        super().__init__(config, plugin_opts)

        if plugin_opts and 'pe_headers' in plugin_opts:
            self.pe_headers = plugin_opts['pe_headers'].encode()
        elif config.has_option('options', 'pe_headers'):
            self.pe_headers = config.get('options', 'pe_headers').encode()

    def scan(self, payload: Payload, request_meta: RequestMeta) -> WorkerResponse:
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
