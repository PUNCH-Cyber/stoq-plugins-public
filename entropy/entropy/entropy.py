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

Calculate shannon entropy of a payload

"""

import math
from typing import Dict
from collections import Counter

from stoq.plugins import WorkerPlugin
from stoq import Payload, Request, WorkerResponse


class Hash(WorkerPlugin):
    async def scan(self, payload: Payload, request: Request) -> WorkerResponse:
        entropy: float = 0.0
        results: Dict[str, float] = {}
        if payload.content:
            occurences = Counter(bytearray(payload.content))
            for bc in occurences.values():
                b = float(bc) / len(payload.content)
                entropy -= b * math.log(b, 2)
        results['entropy'] = entropy
        return WorkerResponse(results=results)
