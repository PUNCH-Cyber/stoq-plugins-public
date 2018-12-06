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

Scan a payload using xorsearch

"""

import os
import tempfile
from pathlib import Path
from typing import Dict, Optional
from subprocess import check_output, run
from configparser import ConfigParser
from inspect import currentframe, getframeinfo

from stoq.plugins import WorkerPlugin
from stoq.exceptions import StoqPluginException
from stoq import Payload, RequestMeta, WorkerResponse


class XorSearchPlugin(WorkerPlugin):
    def __init__(self, config: ConfigParser, plugin_opts: Optional[Dict]) -> None:
        super().__init__(config, plugin_opts)

        bin_path = None
        terms = None

        filename = getframeinfo(currentframe()).filename
        parent = Path(filename).resolve().parent

        if plugin_opts and 'terms' in plugin_opts:
            terms = plugin_opts['terms']
        elif config.has_option('options', 'terms'):
            terms = config.get('options', 'terms')
        if terms:
            if not os.path.isabs(terms):
                terms = os.path.join(parent, terms)
        self.terms = terms

        if plugin_opts and 'bin_path' in plugin_opts:
            bin_path = plugin_opts['bin_path']
        elif config.has_option('options', 'bin_path'):
            bin_path = config.get('options', 'bin_path')
        if bin_path:
            if not os.path.isabs(bin_path):
                bin_path = os.path.join(parent, bin_path)
        self.bin_path = bin_path

    def scan(self, payload: Payload, request_meta: RequestMeta) -> WorkerResponse:
        """
        Scan a payload using xorsearch

        """
        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(payload.content)
            temp_file.flush()
            cmd = [self.bin_path, '-f', self.terms, temp_file.name]
            process_results = check_output(cmd).splitlines()
            print(process_results)

        result = {}
        for line in process_results:
            line = line.decode()
            _, _, key, _, pos, hit = line.split(maxsplit=5)
            # We are going to skip over hits that are not xor'd
            if key != '00':
                key = f'0x{key}'
                if key not in result:
                    result[key] = []
                result[key].append(
                    {'pos': f'0x{pos.replace("(-1):", "")}', 'match': hit}
                )

        return WorkerResponse(result)
