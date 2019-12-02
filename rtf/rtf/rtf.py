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

Extract objects from RTF payloads

"""

from typing import List
from oletools import rtfobj

from stoq.plugins import WorkerPlugin
from stoq import Payload, PayloadMeta, ExtractedPayload, Request, WorkerResponse


class RtfPlugin(WorkerPlugin):
    async def scan(self, payload: Payload, request: Request) -> WorkerResponse:
        extracted: List[ExtractedPayload] = []
        rtf = rtfobj.RtfObjParser(payload.content)
        rtf.parse()

        for obj_idx, obj in enumerate(rtf.objects):
            if obj.is_ole:
                data = obj.oledata
                meta = PayloadMeta(extra_data={'index': obj_idx})
            elif obj.is_package:
                data = obj.olepkgdata
                meta = PayloadMeta(
                    extra_data={'index': obj_idx, 'filename': obj.filename}
                )
            else:
                data = obj.rawdata
                meta = PayloadMeta(extra_data={'index': obj_idx})
            extracted.append(ExtractedPayload(data, meta))
        return WorkerResponse(extracted=extracted)
