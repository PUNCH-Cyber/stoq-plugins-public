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

Scan a payload using xorsearch

"""

import os
import tempfile

from typing import Dict
from pathlib import Path
from asyncio.subprocess import PIPE
from asyncio import create_subprocess_exec
from inspect import currentframe, getframeinfo

from stoq.plugins import WorkerPlugin
from stoq.helpers import StoqConfigParser
from stoq import Payload, Request, WorkerResponse


class XorSearchPlugin(WorkerPlugin):
    def __init__(self, config: StoqConfigParser) -> None:
        super().__init__(config)

        filename = getframeinfo(currentframe()).filename  # type: ignore
        parent = Path(filename).resolve().parent

        self.terms = config.get('options', 'terms', fallback='terms.txt')
        if not os.path.isabs(self.terms):
            self.terms = os.path.join(parent, self.terms)
        self.bin = config.get('options', 'bin_path', fallback='xorsearch')

    async def scan(self, payload: Payload, request: Request) -> WorkerResponse:
        """
        Scan a payload using xorsearch

        """
        result: Dict = {}

        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(payload.content)
            temp_file.flush()
            cmd = [self.bin, '-f', self.terms, temp_file.name]
            p = await create_subprocess_exec(*cmd, stdout=PIPE, stderr=PIPE)
            out, err = await p.communicate()
        for line in out.splitlines():
            _, _, key, _, pos, hit = line.decode().split(maxsplit=5)
            # We are going to skip over hits that are not xor'd
            if key != '00':
                key = f'0x{key}'
                if key not in result:
                    result[key] = []
                result[key].append(
                    {'pos': f'0x{pos.replace("(-1):", "")}', 'match': hit}
                )
        return WorkerResponse(result)
