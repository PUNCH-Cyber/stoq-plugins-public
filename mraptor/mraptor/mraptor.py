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

Port of mraptor3 from oletools

"""

from typing import Dict, List
from oletools import olevba3 as olevba
from oletools.mraptor3 import MacroRaptor

from stoq.plugins import WorkerPlugin
from stoq import Payload, Request, WorkerResponse


class MacroRaptorPlugin(WorkerPlugin):
    FLAGS: Dict[str, str] = {'A': 'AutoExec', 'W': 'Write', 'X': 'Execute'}

    async def scan(self, payload: Payload, request: Request) -> WorkerResponse:
        results: Dict = {}
        filename = payload.results.payload_meta.extra_data.get(
            'filename', payload.results.payload_id
        )
        vba_parser = olevba.VBA_Parser(filename=filename, data=payload.content)

        if vba_parser.detect_vba_macros():
            vba_modules: List[str] = [
                vba_code[3] for vba_code in vba_parser.extract_all_macros()
            ]
            mraptor = MacroRaptor('\n'.join(vba_modules))
            mraptor.scan()
            flags = [
                self.FLAGS[flag] for flag in mraptor.get_flags() if flag in self.FLAGS
            ]
            results = {
                'suspicous': mraptor.suspicious,
                'flags': flags,
                'filetype': vba_parser.type,
                'matches': mraptor.matches,
            }

        return WorkerResponse(results)
