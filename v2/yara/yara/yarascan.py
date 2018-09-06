#!/usr/bin/env python3

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

Process a payload using yara

"""

from configparser import ConfigParser
import os
from typing import Dict, List, Optional

import yara

from stoq import Payload, RequestMeta, WorkerResponse, DispatcherResponse
from stoq.plugins import WorkerPlugin, DispatcherPlugin
from stoq.exceptions import StoqException


class YaraPlugin(WorkerPlugin, DispatcherPlugin):
    def __init__(self, config: ConfigParser,
                 plugin_opts: Optional[Dict]) -> None:
        super().__init__(config, plugin_opts)

        self.dispatch_rules = None
        self.worker_rules = None

        if plugin_opts and "dispatch_rules" in plugin_opts:
            self.dispatch_rules = self.compile_rules(
                plugin_opts["dispatch_rules"])
        elif config.has_option("options", "dispatch_rules"):
            self.dispatch_rules = self.compile_rules(
                config.get("options", "dispatch_rules"))

        if plugin_opts and "yararules" in plugin_opts:
            self.worker_rules = self.compile_rules(
                plugin_opts["worker_rules"])
        elif config.has_option("options", "worker_rules"):
            self.worker_rules = self.compile_rules(
                config.get("options", "worker_rules"))

    def compile_rules(self, filepath: str) -> None:
        filepath = os.path.realpath(filepath)
        if not os.path.isfile(filepath):
            raise StoqException(
                f"Nonexistent yara rules file provided: {filepath}")
        else:
            return yara.compile(filepath=filepath)

    def scan(
            self,
            payload: Payload,
            request_meta: RequestMeta,
    ) -> WorkerResponse:
        matches = self.worker_rules.match(data=payload.content, timeout=60)
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

    def dispatch(self, payload: Payload,
            request_meta: RequestMeta) -> DispatcherResponse:
        dr = DispatcherResponse()
        for match in self._yara_dispatch_matches(payload.content):
            if 'plugin' in match['meta']:
                plugin_str = match['meta']['plugin'].lower().strip()
                plugin_names = {
                    p.strip()
                    for p in plugin_str.split(',') if p.strip()
                }
                for name in plugin_names:
                    if name:
                        if match['meta'].get('save', '').lower().strip() == 'false':
                            payload.payload_meta.should_archive = False
                        name = name.strip()
                        dr.plugin_names.append(name)
                        dr.meta[name] = match
        return dr

    def _yara_dispatch_matches(self, content: bytes) -> List[Dict]:
        if self.dispatch_rules is None:
            return []
        matches = self.dispatch_rules.match(data=content, timeout=60)
        dict_matches = []
        for match in matches:
            dict_matches.append({
                'tags': match.tags,
                'namespace': match.namespace,
                'rule': match.rule,
                'meta': match.meta,
                'strings': match.strings,
            })
        return dict_matches
