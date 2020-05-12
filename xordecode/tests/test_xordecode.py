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

import os
import asynctest

from pathlib import Path

from stoq import RequestMeta, Stoq, Payload
from stoq.data_classes import WorkerResponse


class TestCore(asynctest.TestCase):
    def setUp(self) -> None:
        self.plugin_name = 'xordecode'
        self.base_dir = Path(os.path.realpath(__file__)).parent
        self.plugin_dir = os.path.join(self.base_dir.parent, self.plugin_name)
        self.generic_data = b'This is a payload to XOR decode'
        self.xorkeys = [65]
        self.rolling_xorkeys = [41, 52, 63]

    def tearDown(self) -> None:
        pass

    async def test_scan_xor_single_value(self) -> None:
        s = Stoq(plugin_dir_list=[self.plugin_dir])
        plugin = s.load_plugin(self.plugin_name)
        payload = Payload(self._xor_encode(self.generic_data, self.xorkeys))
        dispatch_meta = {'test': {'test': {'meta': {'xorkey': self.xorkeys}}}}
        payload.dispatch_meta = dispatch_meta
        response = await plugin.scan(payload, RequestMeta())
        self.assertIsInstance(response, WorkerResponse)
        self.assertEqual(self.generic_data, response.extracted[0].content)
        self.assertEqual(
            self.xorkeys, response.extracted[0].payload_meta.extra_data['xorkey']
        )

    async def test_scan_xor_single_value_str(self) -> None:
        s = Stoq(plugin_dir_list=[self.plugin_dir])
        plugin = s.load_plugin(self.plugin_name)
        payload = Payload(self._xor_encode(self.generic_data, self.xorkeys))
        dispatch_meta = {'test': {'test': {'meta': {'xorkey': str(self.xorkeys[0])}}}}
        payload.dispatch_meta = dispatch_meta
        response = await plugin.scan(payload, RequestMeta())
        self.assertIsInstance(response, WorkerResponse)
        self.assertEqual(self.generic_data, response.extracted[0].content)
        self.assertEqual(
            self.xorkeys, response.extracted[0].payload_meta.extra_data['xorkey']
        )

    async def test_scan_xor_single_value_int(self) -> None:
        s = Stoq(plugin_dir_list=[self.plugin_dir])
        plugin = s.load_plugin(self.plugin_name)
        payload = Payload(self._xor_encode(self.generic_data, self.xorkeys))
        dispatch_meta = {'test': {'test': {'meta': {'xorkey': self.xorkeys[0]}}}}
        payload.dispatch_meta = dispatch_meta
        response = await plugin.scan(payload, RequestMeta())
        self.assertIsInstance(response, WorkerResponse)
        self.assertEqual(self.generic_data, response.extracted[0].content)
        self.assertEqual(
            self.xorkeys, response.extracted[0].payload_meta.extra_data['xorkey']
        )

    async def test_scan_xor_rolling_values(self) -> None:
        s = Stoq(plugin_dir_list=[self.plugin_dir])
        plugin = s.load_plugin(self.plugin_name)
        payload = Payload(self._xor_encode(self.generic_data, self.rolling_xorkeys))
        dispatch_meta = {'test': {'test': {'meta': {'xorkey': self.rolling_xorkeys}}}}
        payload.dispatch_meta = dispatch_meta
        response = await plugin.scan(payload, RequestMeta())
        self.assertIsInstance(response, WorkerResponse)
        self.assertEqual(self.generic_data, response.extracted[0].content)
        self.assertEqual(
            self.rolling_xorkeys,
            response.extracted[0].payload_meta.extra_data['xorkey'],
        )

    async def test_scan_xor_rolling_values_str(self) -> None:
        s = Stoq(plugin_dir_list=[self.plugin_dir])
        plugin = s.load_plugin(self.plugin_name)
        payload = Payload(self._xor_encode(self.generic_data, self.rolling_xorkeys))
        dispatch_meta = {
            'test': {
                'test': {
                    'meta': {'xorkey': ",".join([str(i) for i in self.rolling_xorkeys])}
                }
            }
        }
        payload.dispatch_meta = dispatch_meta
        response = await plugin.scan(payload, RequestMeta())
        self.assertIsInstance(response, WorkerResponse)
        self.assertEqual(self.generic_data, response.extracted[0].content)
        self.assertEqual(
            self.rolling_xorkeys,
            response.extracted[0].payload_meta.extra_data['xorkey'],
        )

    @staticmethod
    def _xor_encode(payload, keys):
        last_rolling_index = len(keys) - 1
        current_rolling_index = 0
        payload_bytes = bytearray(payload)

        for index in range(len(payload)):
            xor_value = keys[current_rolling_index]
            payload_bytes[index] ^= xor_value
            if current_rolling_index < last_rolling_index:
                current_rolling_index += 1
            else:
                current_rolling_index = 0
        return bytes(payload_bytes)
