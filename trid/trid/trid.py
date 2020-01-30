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

Identify file types from their TrID signature

"""

import os
import re
import tempfile
from pathlib import Path
from subprocess import Popen, PIPE
from collections import defaultdict
from inspect import currentframe, getframeinfo
from typing import DefaultDict, Dict, List, Optional

from stoq.plugins import WorkerPlugin
from stoq.helpers import StoqConfigParser
from stoq.exceptions import StoqPluginException
from stoq import Error, Payload, Request, WorkerResponse


class TridPlugin(WorkerPlugin):
    def __init__(self, config: StoqConfigParser) -> None:
        super().__init__(config)

        filename = getframeinfo(currentframe()).filename
        parent = Path(filename).resolve().parent

        self.bin = config.get('options', 'bin', fallback='trid')
        self.skip_warnings = config.getlist(
            'options', 'skip_warnings', fallback=['file seems to be plain text/ASCII']
        )
        self.trid_defs = config.get('options', 'trid_defs', fallback='triddefs.trd')
        if not os.path.isabs(self.trid_defs) and self.trid_defs:
            self.trid_defs = os.path.join(parent, self.trid_defs)
        if not os.path.isfile(self.trid_defs):
            raise StoqPluginException(
                f'TrID definitions do not exist at {self.trid_defs}'
            )

    async def scan(self, payload: Payload, request: Request) -> WorkerResponse:
        """
        Scan a payload using TRiD

        """
        results: DefaultDict = defaultdict(list)
        errors: List[Error] = []
        unknown_ext: int = 0

        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(payload.content)
            temp_file.flush()
            p = Popen(
                [self.bin, f"-d:{self.trid_defs}", temp_file.name],
                stdout=PIPE,
                stderr=PIPE,
                env={'LC_ALL': 'C'},
                universal_newlines=True,
            )
            trid_results, err = p.communicate()
            if err:
                errors.append(
                    Error(
                        error=err,
                        plugin_name=self.plugin_name,
                        payload_id=payload.results.payload_id,
                    )
                )

        matches = re.findall(r'^ {0,2}[0-9].*%.*$', trid_results, re.M)
        warnings = re.findall(r'^Warning: (.*$)', trid_results, re.M)
        errors.extend(
            [
                Error(
                    error=w,
                    plugin_name=self.plugin_name,
                    payload_id=payload.results.payload_id,
                )
                for w in warnings
                if w not in self.skip_warnings
            ]
        )
        for match in matches:
            match = match.split()
            if match:
                try:
                    ext = match[1].strip('(.)')
                    if not ext:
                        ext = f'UNK{unknown_ext}'
                        unknown_ext += 1
                    results[ext].append(
                        {'likely': match[0], 'type': ' '.join(match[2:])}
                    )
                except IndexError:
                    continue
        return WorkerResponse(results, errors=errors)
