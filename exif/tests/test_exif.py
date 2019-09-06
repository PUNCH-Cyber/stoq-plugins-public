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
        self.plugin_name = 'exif'
        self.base_dir = Path(os.path.realpath(__file__)).parent
        self.data_dir = os.path.join(self.base_dir, 'data')
        self.plugin_dir = os.path.join(self.base_dir.parent, self.plugin_name)

    def tearDown(self) -> None:
        pass

    def test_scan(self) -> None:
        s = Stoq(plugin_dir_list=[self.plugin_dir])
        plugin = s.load_plugin(self.plugin_name)
        with open(f'{self.data_dir}/sample.pdf', 'rb') as f:
            payload = Payload(f.read())
        response = plugin.scan(payload, RequestMeta())
        self.assertIsInstance(response, WorkerResponse)
        self.assertIn('FileType', response.results)
        self.assertEqual('PDF', response.results['FileType'])
        self.assertEqual(6, response.results['PageCount'])

    def test_version(self) -> None:
        s = Stoq(plugin_dir_list=[self.plugin_dir])
        plugin = s.load_plugin(self.plugin_name)
        version_info = plugin.version_info()
        self.assertIn('ExifToolVersion', version_info)
        self.assertIn('PluginVersion', version_info)
        self.assertEqual(version_info['PluginVersion'], '2.0.3')
