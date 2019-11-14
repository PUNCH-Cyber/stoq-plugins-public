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

Extract object from TNEF payloads

"""

from typing import List
from tnefparse import TNEF
from bs4 import UnicodeDammit

from stoq.plugins import WorkerPlugin
from stoq import Payload, Request, WorkerResponse, ExtractedPayload, PayloadMeta


class TNEFExtractorPlugin(WorkerPlugin):
    async def scan(self, payload: Payload, request: Request) -> WorkerResponse:
        extracted: List[ExtractedPayload] = []
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
        return WorkerResponse(extracted=extracted)
