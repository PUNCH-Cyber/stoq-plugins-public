#   Copyright 2014-2019 PUNCH Cyber Analytics Group
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

Parse and abstract PE, ELF and MachO files using LIEF

"""

import json
import lief
from typing import Dict, Optional
from configparser import ConfigParser

from stoq.plugins import WorkerPlugin
from stoq.exceptions import StoqPluginException
from stoq import Payload, RequestMeta, WorkerResponse


class LiefPlugin(WorkerPlugin):
    def __init__(self, config: ConfigParser, plugin_opts: Optional[Dict]) -> None:
        super().__init__(config, plugin_opts)

        self.abstract = True

        if plugin_opts and 'abstract' in plugin_opts:
            self.abstract = bool(plugin_opts['abstract'])
        elif config.has_option('options', 'abstract'):
            self.abstract = bool(config.get('options', 'abstract'))

    def scan(self, payload: Payload, request_meta: RequestMeta) -> WorkerResponse:
        """
        Scan a payload using LIEF

        """
        filename = payload.payload_meta.extra_data.get('filename', payload.payload_id)

        try:
            binary = lief.parse(raw=payload.content, name=filename)
        except lief.exception as err:
            raise StoqPluginException(f'Unable to parse payload: {err}')

        if binary is None:
            raise StoqPluginException('The file type isn\'t supported by LIEF')

        if self.abstract == True:
            results = lief.to_json_from_abstract(binary.abstract)
        else:
            results = lief.to_json(binary)

        return WorkerResponse(json.loads(results))
