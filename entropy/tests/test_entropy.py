#!/usr/bin/env python3

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

import os
import unittest
from pathlib import Path

from stoq import RequestMeta, Stoq, Payload
from stoq.data_classes import WorkerResponse


class TestCore(unittest.TestCase):
    def setUp(self) -> None:
        self.plugin_name = 'entropy'
        self.base_dir = Path(os.path.realpath(__file__)).parent
        self.data_dir = os.path.join(self.base_dir, 'data')
        self.plugin_dir = os.path.join(self.base_dir.parent, self.plugin_name)
        self.entropy_nil = b'a' * 256
        self.entropy_not_nil = b'abc' * 256

    def tearDown(self) -> None:
        pass

    def test_scan_nil(self) -> None:
        s = Stoq(plugin_dir_list=[self.plugin_dir])
        plugin = s.load_plugin(self.plugin_name)
        payload = Payload(self.entropy_nil)
        response = plugin.scan(payload, RequestMeta())
        self.assertIsInstance(response, WorkerResponse)
        self.assertEqual(0.0, response.results['entropy'])

    def test_scan_notnil(self) -> None:
        s = Stoq(plugin_dir_list=[self.plugin_dir])
        plugin = s.load_plugin(self.plugin_name)
        payload = Payload(self.entropy_not_nil)
        response = plugin.scan(payload, RequestMeta())
        self.assertIsInstance(response, WorkerResponse)
        self.assertEqual(1.584962500721156, response.results['entropy'])
