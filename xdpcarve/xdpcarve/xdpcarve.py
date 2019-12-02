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

Carve and decode elements from XDP objects

"""

import base64
from typing import Dict, List, Optional
from xml.dom.minidom import parseString
from xml.parsers.expat import ExpatError

from stoq.plugins import WorkerPlugin
from stoq.helpers import StoqConfigParser
from stoq import Error, Payload, PayloadMeta, ExtractedPayload, Request, WorkerResponse


class XdpCarve(WorkerPlugin):
    def __init__(self, config: StoqConfigParser) -> None:
        super().__init__(config)
        self.elements = config.getlist('options', 'elements', fallback=['chunk'])

    async def scan(self, payload: Payload, request: Request) -> WorkerResponse:
        extracted: List[ExtractedPayload] = []
        errors: List[Error] = []
        try:
            parsed_xml = parseString(payload.content)
        except ExpatError as err:
            errors.append(
                Error(
                    error=f'Unable to parse payload as XML with xdpcarve: {err}',
                    plugin_name=self.plugin_name,
                    payload_id=payload.results.payload_id,
                )
            )
            return WorkerResponse(errors=errors)
        for name in self.elements:
            dom_element = parsed_xml.getElementsByTagName(name)
            for dom in dom_element:
                content = dom.firstChild.nodeValue
                content = content.rstrip()
                try:
                    content = base64.b64decode(content)
                except:
                    pass
                meta = PayloadMeta(extra_data={'element_name': name})
                extracted.append(ExtractedPayload(content, meta))
        return WorkerResponse(extracted=extracted, errors=errors)
