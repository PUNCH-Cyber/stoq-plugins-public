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

Carve and decode elements from XDP objects

"""

import base64
from typing import Dict, Optional
from configparser import ConfigParser
from xml.dom.minidom import parseString
from xml.parsers.expat import ExpatError

from stoq.plugins import WorkerPlugin
from stoq import Payload, PayloadMeta, ExtractedPayload, RequestMeta, WorkerResponse


class XdpCarve(WorkerPlugin):
    def __init__(self, config: ConfigParser, plugin_opts: Optional[Dict]) -> None:
        super().__init__(config, plugin_opts)

        if plugin_opts and 'elements' in plugin_opts:
            self.ioc_keys = plugin_opts['elements']
        elif config.has_option('options', 'elements'):
            self.elements = [
                x.strip() for x in config.get('options', 'elements').split(',')
            ]

    def scan(self, payload: Payload, request_meta: RequestMeta) -> WorkerResponse:
        extracted = []
        errors = []
        try:
            parsed_xml = parseString(payload.content)
        except ExpatError as err:
            errors.append(f'Unable to parse payload as XML with xdpcarve: {err}')
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
                meta = PayloadMeta(extra_data={"element_name": name})
                extracted.append(ExtractedPayload(content, meta))
        return WorkerResponse(extracted=extracted, errors=errors)
