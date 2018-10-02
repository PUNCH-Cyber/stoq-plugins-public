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

Extract object from TNEF payloads

"""

from configparser import ConfigParser
from typing import Dict, Optional
from tnefparse import TNEF
from bs4 import UnicodeDammit

from stoq import (
    Payload, RequestMeta, WorkerResponse,
    ExtractedPayload, PayloadMeta)
from stoq.plugins import WorkerPlugin


class TNEFExtractorPlugin(WorkerPlugin):

    def __init__(self, config: ConfigParser,
                 plugin_opts: Optional[Dict]) -> None:
        super().__init__(config, plugin_opts)

    def scan(
            self,
            payload: Payload,
            request_meta: RequestMeta,
    ) -> WorkerResponse:

        extracted = []
        tnef_results = TNEF(payload.content)

        if tnef_results.attachments:
            for tnef_attachment in tnef_results.attachments:
                try:
                    filename = UnicodeDammit(tnef_attachment.name).unicode_markup
                except:
                    filename = "None"
                tnef_meta = PayloadMeta(extra_data={'filename': filename})
                attachment = ExtractedPayload(tnef_attachment.data, tnef_meta)
                extracted.extend(attachment)

        return WorkerResponse({}, extracted=extracted)
