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

Processes a payload using ExifTool

"""

import json
from subprocess import PIPE, Popen
from typing import Dict, List, Optional

from stoq.plugins import WorkerPlugin
from stoq.helpers import StoqConfigParser
from stoq.exceptions import StoqPluginException
from stoq import Error, Payload, Request, WorkerResponse


class ExifToolPlugin(WorkerPlugin):
    def __init__(self, config: StoqConfigParser) -> None:
        super().__init__(config)
        self.bin = config.get('options', 'bin', fallback='exiftool')

    async def scan(self, payload: Payload, request: Request) -> WorkerResponse:
        """
        Scan a payload using Exiftool

        """
        errors: List[Error] = []
        try:
            cmd = [self.bin, '-j', '-n', '-']
            p = Popen(cmd, stdout=PIPE, stdin=PIPE)
            out, err = p.communicate(input=payload.content)
            results = json.loads(out)[0]
        except Exception as err:
            errors.append(
                Error(err, plugin_name=self.plugin_name, payload_id=payload.payload_id)
            )
        return WorkerResponse(results, errors=errors)
