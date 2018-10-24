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

Ingest a file or directory for processing

"""

import os
from queue import Queue
from typing import Dict, Optional
from configparser import ConfigParser

from stoq import Payload, PayloadMeta
from stoq.plugins import ProviderPlugin
from stoq.exceptions import StoqPluginException


class FileDirPlugin(ProviderPlugin):
    def __init__(self, config: ConfigParser, plugin_opts: Optional[Dict]) -> None:
        super().__init__(config, plugin_opts)

        if plugin_opts and 'source_dir' in plugin_opts:
            self.source_dir = plugin_opts['source_dir']
        elif config.has_option('options', 'source_dir'):
            self.source_dir = config.get('options', 'source_dir')
        else:
            self.source_dir = None
        if not self.source_dir:
            raise StoqPluginException('Source directory not defined')

        if plugin_opts and 'recursive' in plugin_opts:
            self.recursive = plugin_opts['recursive']
        elif config.has_option('options', 'recursive'):
            self.recursive = config.get('options', 'recursive')
        else:
            self.recursive = False

    def ingest(self, queue: Queue) -> None:
        """
        Ingest files from a directory

        """
        if os.path.isdir(self.source_dir):
            if self.recursive:
                for root_path, subdirs, files in os.walk(self.source_dir):
                    for entry in files:
                        path = os.path.join(root_path, entry)
                        self._queue(path, queue)
            else:
                for entry in os.scandir(self.source_dir):
                    if not entry.name.startswith('.') and entry.is_file():
                        path = os.path.join(self.source_dir, entry.name)
                        self._queue(path, queue)
        elif os.path.isfile(self.source_dir):
            self._queue(path, queue)

    def _queue(self, path: str, queue: Queue) -> None:
        meta = PayloadMeta(
            extra_data={
                'filename': os.path.basename(path),
                'source_dir': os.path.dirname(path),
            }
        )
        with open(path, "rb") as f:
            queue.put(Payload(f.read(), meta))
