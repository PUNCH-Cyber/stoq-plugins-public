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

Upload content to a Tika server for automated text extraction

"""

import requests
from typing import Dict, Optional
from configparser import ConfigParser

from stoq.plugins import WorkerPlugin
from stoq import Payload, RequestMeta, WorkerResponse, ExtractedPayload


class TikaPlugin(WorkerPlugin):
    def __init__(self, config: ConfigParser, plugin_opts: Optional[Dict]) -> None:
        super().__init__(config, plugin_opts)

        self.tika_url = None

        if plugin_opts and 'tika_url' in plugin_opts:
            self.tika_url = plugin_opts['tika_url']
        elif config.has_option('options', 'tika_url'):
            self.tika_url = config.get('options', 'tika_url')

        if plugin_opts and 'tika_save_text' in plugin_opts:
            self.tika_save_text = plugin_opts['tika_save_text']
        elif config.has_option('options', 'tika_save_text'):
            self.tika_save_text = config.get('options', 'tika_save_text')
            
    def scan(self, payload: Payload, request_meta: RequestMeta) -> WorkerResponse:
        """
        Upload content to a Tika server for automated text extraction

        """
        response = requests.put(self.tika_url, data=payload.content)
        response.raise_for_status()
        extracted = ExtractedPayload(response.content)
        if self.tika_save_text:
            return WorkerResponse(results=extracted, extracted=[extracted])
        return WorkerResponse(extracted=[extracted])
