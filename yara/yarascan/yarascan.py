#!/usr/bin/env python3

#   Copyright 2014-present PUNCH Cyber Analytics Group
#
#   Licensed under the Apache License, Version 2.0 (the 'License');
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an 'AS IS' BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
"""
Overview
========

Process a payload using yara

"""

import os
import yara

from pathlib import Path
from typing import Dict, Generator
from inspect import currentframe, getframeinfo

from stoq.helpers import StoqConfigParser
from stoq.exceptions import StoqPluginException
from stoq.plugins import WorkerPlugin, DispatcherPlugin
from stoq import Payload, Request, WorkerResponse, DispatcherResponse


class YaraPlugin(WorkerPlugin, DispatcherPlugin):
    def __init__(self, config: StoqConfigParser) -> None:
        super().__init__(config)

        self.dispatch_rules = None
        self.worker_rules = None
        filename = getframeinfo(currentframe()).filename  # type: ignore
        parent = Path(filename).resolve().parent

        self.timeout = config.getint('options', 'timeout', fallback=60)
        self.strings_limit = config.getint('options', 'strings_limit', fallback=None)
        self.xor_first_match = config.getboolean('options', 'xor_first_match', fallback=True)
        dispatch_ruleset = config.get(
            'options', 'dispatch_rules', fallback='rules/dispatcher.yar'
        )
        if dispatch_ruleset:
            if not os.path.isabs(dispatch_ruleset):
                dispatch_ruleset = os.path.join(parent, dispatch_ruleset)
            self.dispatch_rules = self._compile_rules(dispatch_ruleset)

        worker_ruleset = config.get(
            'options', 'worker_rules', fallback='rules/stoq.yar'
        )
        if worker_ruleset:
            if not os.path.isabs(worker_ruleset):
                worker_ruleset = os.path.join(parent, worker_ruleset)
            self.worker_rules = self._compile_rules(worker_ruleset)

    async def scan(self, payload: Payload, request: Request) -> WorkerResponse:
        results = {
            'matches': [
                m for m in self._yara_matches(payload.content, self.worker_rules)
            ]
        }
        return WorkerResponse(results=results)

    async def get_dispatches(
        self, payload: Payload, request: Request
    ) -> DispatcherResponse:
        dr = DispatcherResponse()
        for match in self._yara_matches(payload.content, self.dispatch_rules):
            if match['meta'].get('save', '').lower().strip() == 'false':
                payload.results.payload_meta.should_archive = False
            plugin_names = self._extract_plugin_names(match)
            if 'xordecode' in plugin_names:
                self._plugin_xor_extract_key(match)
            for name in plugin_names:
                dr.plugin_names.append(name)
                dr.meta[name] = match
        return dr

    def _compile_rules(self, filepath: str) -> yara:
        filepath = os.path.realpath(filepath)
        if not os.path.isfile(filepath):
            raise StoqPluginException(
                f'Nonexistent yara rules file provided: {filepath}'
            )
        else:
            return yara.compile(filepath=filepath)

    def _yara_matches(self, content: bytes, rules: yara) -> Generator[Dict, None, None]:
        matches = rules.match(data=content, timeout=self.timeout)
        for match in matches:
            yield {
                'tags': match.tags,
                'namespace': match.namespace,
                'rule': match.rule,
                'meta': match.meta,
                'strings': match.strings[: self.strings_limit],
            }

    def _extract_plugin_names(self, match: dict) -> set:
        plugin_names = set()
        if 'meta' in match:
            plugin_str = match['meta'].get('plugin', '').lower().strip()
            plugin_names.update({p.strip() for p in plugin_str.split(',') if p.strip()})
        return plugin_names

    def _plugin_xor_extract_key(self, match: dict) -> None:
        # Extract XOR key using plaintext in metadata against strings, see YARA issue #1242 for known issues
        if 'strings' not in match or 'meta' not in match:
            return
        xor_pt_prefix = 'xor_plaintext_for_string_'
        xor_info = []
        xor_pt = {'$' + k[len(xor_pt_prefix):]: v for k, v in match['meta'].items() if k.startswith(xor_pt_prefix) and v}
        if xor_pt:
            for offset, label, match_bytes in match['strings']:
                if label not in xor_pt:
                    continue
                xor_pt_bytes = bytes(xor_pt[label], 'utf8')
                if len(xor_pt_bytes) != len(match_bytes):
                    continue
                key = self._xor_extract_key(match_bytes, xor_pt_bytes)
                if key and self.xor_first_match:
                    xorkey = key[0] if len(key) == 1 else bytes(key)
                    match['meta']['xorkey'] = repr(xorkey)
                    return
                elif key:
                    xor_info.append((offset, label, key))
            if xor_info:
                match['meta']['xor_info'] = xor_info

    def _xor_extract_key(self, ct_bytes, pt_bytes) -> bytes:
        key_list = bytearray(a ^ b for (a, b) in zip(pt_bytes, ct_bytes))
        keys_len = len(key_list)
        for i in range(1, keys_len):
            sub_key = key_list[:i]
            overlap_key = sub_key * (1 + keys_len // i)
            if overlap_key[:keys_len] == key_list:
                key = bytes(sub_key)
                return key
