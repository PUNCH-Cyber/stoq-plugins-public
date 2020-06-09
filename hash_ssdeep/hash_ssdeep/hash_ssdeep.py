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

Generate a ssdeep hash of payload

"""

import ssdeep
from asyncio import sleep

from stoq.plugins import WorkerPlugin
from stoq import Payload, Request, WorkerResponse


class HashSSDeep(WorkerPlugin):
    async def scan(self, payload: Payload, request: Request) -> WorkerResponse:
        secure_hashes = {
            'ssdeep': ssdeep.Hash(),
        }
        block_size = 2 ** 24  # Pass control back to asyncio loop every 16MB
        for block_index in range(0, len(payload.content), block_size):
            for function in secure_hashes.keys():
                secure_hashes[function].update(payload.content[block_index:block_index + block_size])
                await sleep(0)
        for function in secure_hashes.keys():
            if hasattr(secure_hashes[function], 'hexdigest'):
                secure_hashes[function] = secure_hashes[function].hexdigest()
            else:
                secure_hashes[function] = secure_hashes[function].digest()
        return WorkerResponse(
            results=secure_hashes
        )
