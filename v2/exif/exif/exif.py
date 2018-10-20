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
from subprocess import check_output

from stoq.plugins import WorkerPlugin
from stoq import Payload, RequestMeta, WorkerResponse


class ExifToolPlugin(WorkerPlugin):
    def __init__(self, config: ConfigParser, plugin_opts: Optional[Dict]) -> None:
        super().__init__(config, plugin_opts)

        if plugin_opts and 'exiftool' in plugin_opts:
            self.exiftool = plugin_opts['exiftool']
        elif config.has_option('options', 'exiftool'):
            self.exiftool = config.getboolean('options', 'exiftool')

    def scan(self, payload: Payload, request_meta: RequestMeta) -> WorkerResponse:
        """
        Scan a payload using Exiftool

        """

        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(payload.content)
            temp_file.flush()
            try:
                cmd = [self.exiftool, '-j', '-n', temp_file.name]
                results = json.loads(check_output(cmd))[0]
            except Exception as err:
                raise StoqException(f'Failed gathering exif data: {err}')

        return WorkerResponse(results)
