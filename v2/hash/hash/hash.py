#!/usr/bin/env python3

#   Copyright 2014-2015 PUNCH Cyber Analytics Group
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

Hash a payload

"""

from hashlib import md5, sha1, sha256

from stoq.plugins import WorkerPlugin
from stoq import Payload, RequestMeta, WorkerResponse


class Hash(WorkerPlugin):
    def scan(self, payload: Payload, request_meta: RequestMeta) -> WorkerResponse:

        return WorkerResponse(
            results={
                'sha256': sha256(payload.content).hexdigest(),
                'md5': md5(payload.content).hexdigest(),
                'sha1': sha1(payload.content).hexdigest(),
            }
        )
