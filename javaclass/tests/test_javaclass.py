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
import yara
import logging
import unittest
from unittest.mock import create_autospec, Mock

from stoq import PayloadMeta, RequestMeta, Stoq, Payload
from stoq.exceptions import StoqPluginException
from stoq.data_classes import WorkerResponse, DispatcherResponse


class TestCore(unittest.TestCase):
    def setUp(self) -> None:
        self.plugin_name = 'javaclass'
        self.plugin_dir = os.path.join(os.getcwd(), 'javaclass')
        self.data_dir = os.path.join(os.getcwd(), 'tests', 'data')
        self.generic_data = b''
        logging.disable(logging.CRITICAL)

    def tearDown(self) -> None:
        logging.disable(logging.NOTSET)

    def test_scan(self) -> None:
        s = Stoq(plugin_dir_list=[self.plugin_dir])
        plugin = s.load_plugin(self.plugin_name)
        with open(f'{self.data_dir}/TestJavaClass.class', 'rb') as f:
            payload = Payload(f.read())
        request_meta = RequestMeta(archive_payloads=False)
        response = plugin.scan(payload, request_meta)
        print(response)
        self.assertIsInstance(response, WorkerResponse)
        self.assertIn('TestJavaClass', response.results['provided'])
        self.assertGreaterEqual(len(response.results['provided']), 4)
        self.assertGreaterEqual(len(response.results['required']), 2)
        self.assertGreaterEqual(len(response.results['constants']), 10)

    def test_scan_invalid_payload(self) -> None:
        s = Stoq(plugin_dir_list=[self.plugin_dir])
        plugin = s.load_plugin(self.plugin_name)
        payload = Payload(b'definitely not a javaclass payload')
        request_meta = RequestMeta(archive_payloads=False)
        with self.assertRaises(StoqPluginException):
            response = plugin.scan(payload, request_meta)
