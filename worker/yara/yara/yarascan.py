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

Process a payload using yara

"""

from configparser import ConfigParser
import os
from typing import Dict, List, Optional

import yara

from stoq import Payload, RequestMeta, StoqException, WorkerResponse
from stoq.plugins import WorkerPlugin


class YaraScan(WorkerPlugin):
    def __init__(self, config: ConfigParser,
                 plugin_opts: Optional[Dict]) -> None:
        super().__init__(config, plugin_opts)
        if plugin_opts and "yararules" in plugin_opts:
            self.set_rules_path(plugin_opts["yararules"])
        elif config.has_option("options", "yararules"):
            self.set_rules_path(config.get("options", "yararules"))
        else:
            raise StoqException("No yara rules file provided")

    def set_rules_path(self, filepath: str) -> None:
        if not os.path.isfile(filepath):
            raise StoqException(
                f"Nonexistent yara rules file provided: {filepath}")
        else:
            self.compiled_rules = yara.compile(filepath=filepath)

    def scan(
            self,
            payload: Payload,
            dispatch_rules: Optional[List[Dict]],
            request_meta: RequestMeta,
    ) -> WorkerResponse:
        matches = self.compiled_rules.match(data=payload.content, timeout=60)
        dict_matches = []
        for match in matches:
            dict_matches.append({
                'tags': match.tags,
                'namespace': match.namespace,
                'rule': match.rule,
                'meta': match.meta,
                'strings': match.strings,
            })
        results = {
            "matches": dict_matches,
        }
        return WorkerResponse(results=results)
