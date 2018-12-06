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

import os
import logging
import unittest

from pathlib import Path

from stoq import RequestMeta, Stoq, Payload
from stoq.data_classes import WorkerResponse
import stoq.tests.utils as utils


class TestCore(unittest.TestCase):
    def setUp(self) -> None:
        self.plugin_name = 'xorsearch'
        self.base_dir = Path(os.path.realpath(__file__)).parent
        self.data_dir = os.path.join(self.base_dir, 'data')
        self.plugin_dir = os.path.join(self.base_dir.parent, self.plugin_name)
        self.generic_data = b'MZAdjustTokenPrivileges CurrentVersion'

    def tearDown(self) -> None:
        pass

    def test_scan(self) -> None:
        s = Stoq(plugin_dir_list=[self.plugin_dir])
        plugin = s.load_plugin(self.plugin_name)
        request_meta = RequestMeta(archive_payloads=False)
        xord = bytes(x ^ 92 for x in self.generic_data)
        payload = Payload(xord)
        response = plugin.scan(payload, request_meta)
        self.assertIsInstance(response, WorkerResponse)
        self.assertIn('0x5C', response.results)
        self.assertEqual(
            'AdjustTokenPrivileges CurrentVersion', response.results['0x5C'][0]['match']
        )
        self.assertEqual('CurrentVersion', response.results['0x5C'][1]['match'])
