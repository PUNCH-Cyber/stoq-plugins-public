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

Decode XOR encoded payloads

"""


import dpath.util

from typing import Union, List

from stoq.plugins import WorkerPlugin
from stoq import Payload, PayloadMeta, ExtractedPayload, Request, WorkerResponse


class XorDecode(WorkerPlugin):
    async def scan(self, payload: Payload, request: Request) -> WorkerResponse:
        xorkey: Union[List[int], str, int, None] = dpath.util.get(
            payload.dispatch_meta, '**/xorkey', default=None
        )

        if not xorkey:
            return
        elif isinstance(xorkey, str):
            xorkey = [int(k.strip()) for k in xorkey.split(',')]
        elif isinstance(xorkey, int):
            xorkey = [xorkey]

        last_rolling_index = len(xorkey) - 1
        current_rolling_index = 0
        payload_bytes = bytearray(payload.content)

        for index in range(payload.results.size):
            xor_value = xorkey[current_rolling_index]
            payload_bytes[index] ^= xor_value
            if current_rolling_index < last_rolling_index:
                current_rolling_index += 1
            else:
                current_rolling_index = 0

        payload.results.payload_meta.extra_data['xorkey'] = xorkey
        meta = PayloadMeta(extra_data={'xorkey': xorkey})
        extracted = [ExtractedPayload(bytes(payload_bytes), meta)]
        return WorkerResponse(extracted=extracted)
