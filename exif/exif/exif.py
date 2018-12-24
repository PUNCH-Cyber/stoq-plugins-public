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

Processes a payload using ExifTool

"""

import json
import tempfile
from typing import Dict, Optional
from configparser import ConfigParser
from subprocess import run, PIPE

from stoq.plugins import WorkerPlugin

from stoq.exceptions import StoqPluginException
from stoq import Payload, RequestMeta, WorkerResponse


class ExifToolPlugin(WorkerPlugin):
    def __init__(self, config: ConfigParser, plugin_opts: Optional[Dict]) -> None:
        super().__init__(config, plugin_opts)

        if plugin_opts and 'bin_path' in plugin_opts:
            self.bin_path = plugin_opts['bin_path']
        elif config.has_option('options', 'bin_path'):
            self.bin_path = config.get('options', 'bin_path')

    def scan(self, payload: Payload, request_meta: RequestMeta) -> WorkerResponse:
        """
        Scan a payload using Exiftool

        """
        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(payload.content)
            temp_file.flush()
            try:
                cmd = [self.bin_path, '-j', '-n', temp_file.name]
                output = run(cmd, stdout=PIPE)
                results = json.loads(output.stdout)[0]
            except Exception as err:
                raise StoqPluginException(f'Failed gathering exif data: {err}')
        return WorkerResponse(results)
