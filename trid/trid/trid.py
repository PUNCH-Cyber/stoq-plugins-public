#   Copyright 2014-2018 PUNCH Cyber Analytics Group
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
import tempfile
from pathlib import Path
from subprocess import Popen, PIPE
from collections import defaultdict
from configparser import ConfigParser
from inspect import currentframe, getframeinfo
from typing import DefaultDict, Dict, Optional

from stoq.plugins import WorkerPlugin
from stoq.exceptions import StoqPluginException
from stoq import Payload, RequestMeta, WorkerResponse


class TridPlugin(WorkerPlugin):
    def __init__(self, config: ConfigParser, plugin_opts: Optional[Dict]) -> None:
        super().__init__(config, plugin_opts)

        self.trid_defs = 'triddefs.trd'
        self.bin_path = 'trid'
        filename = getframeinfo(currentframe()).filename
        parent = Path(filename).resolve().parent

        if plugin_opts and 'trid_defs' in plugin_opts:
            self.trid_defs = plugin_opts['trid_defs']
        elif config.has_option('options', 'trid_defs'):
            self.trid_defs = config.get('options', 'trid_defs')
        if not os.path.isabs(self.trid_defs) and self.trid_defs:
            self.trid_defs = os.path.join(parent, self.trid_defs)
        if not self.trid_defs or not os.path.isfile(self.trid_defs):
            raise StoqPluginException(
                f'TrID definitions do not exist at {self.trid_defs}'
            )

        if plugin_opts and 'bin_path' in plugin_opts:
            self.bin_path = plugin_opts['bin_path']
        elif config.has_option('options', 'bin_path'):
            self.bin_path = config.get('options', 'bin_path')

    def scan(self, payload: Payload, request_meta: RequestMeta) -> WorkerResponse:
        """
        Scan a payload using TRiD

        """
        results: DefaultDict = defaultdict(list)

        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(payload.content)
            temp_file.flush()
            p = Popen(
                [self.bin_path, f"-d:{self.trid_defs}", temp_file.name],
                stdout=PIPE,
                stderr=PIPE,
                env={'LC_ALL': 'C'},
                universal_newlines=True,
            )
            trid_results, err = p.communicate()
            errors = [err] if err else None

        unknown_ext = 0
        for line in trid_results.splitlines()[6:]:
            if line.startswith('Warning'):
                break
            line = line.split()
            if line:
                try:
                    ext = line[1].strip('(.)')
                    if not ext:
                        ext = f'UNK{unknown_ext}'
                        unknown_ext += 1
                    results[ext].append({'likely': line[0], 'type': ' '.join(line[2:])})
                except IndexError:
                    continue

        return WorkerResponse(results, errors=errors)
