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

Determine mimetype of a payload

"""

import magic

from stoq.plugins import WorkerPlugin
from stoq import Payload, RequestMeta, WorkerResponse

# This is silly. python-magic is the preferred library as it is maintained.
# But, sometimes filemagic is used by other libraries. Let's determine which
# one is installed so we can call it properly.
if hasattr(magic.Magic, "from_buffer"):
    USE_PYTHON_MAGIC = True
else:
    USE_PYTHON_MAGIC = False


class MimeType(WorkerPlugin):
    def scan(self, payload: Payload, request_meta: RequestMeta) -> WorkerResponse:
        if USE_PYTHON_MAGIC:
            magic_scan = magic.Magic(mime=True)
            magic_result = magic_scan.from_buffer(payload.content[0:1000])
        else:
            if mime:
                flags = magic.MAGIC_MIME_TYPE
            else:
                flags = None
            with magic.Magic(flags=flags) as m:
                magic_result = m.id_buffer(payload.content[0:1000])
        if hasattr(magic_result, 'decode'):
            magic_result = magic_result.decode('utf-8')
        return WorkerResponse(results={'mimetype': magic_result})
