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

Decode base64 encoded payloads

"""

from asyncio import sleep
from base64 import b64decode
from re import sub

from stoq.plugins import WorkerPlugin
from stoq import ExtractedPayload, Payload, Request, WorkerResponse


class B64Decode(WorkerPlugin):
    async def scan(self, payload: Payload, request: Request) -> WorkerResponse:
        decoded_content = b''
        remainder = b''
        block_size = 2 ** 24  # Pass control back to asyncio loop every 16MB
        for block_index in range(0, len(payload.content), block_size):
            block = remainder + sub(rb'[^A-Za-z0-9+/=]', b'', payload.content[block_index:block_index + block_size])
            remainder_index = - (len(block) % 4)
            if remainder_index:
                decoded_content += b64decode(block[:remainder_index])
                remainder = block[remainder_index:]
            else:
                decoded_content += b64decode(block)
                remainder = b''
            if b'=' in block:
                break
            await sleep(0)
        if remainder:
            remainder = remainder.ljust(len(remainder)//4 + 4, b'=')
            decoded_content += b64decode(remainder)
        extracted = [ExtractedPayload(decoded_content)]
        return WorkerResponse(extracted=extracted)
