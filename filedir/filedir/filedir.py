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

Handle file and directory interactions

"""

import os
import hashlib
from queue import Queue
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional
from configparser import ConfigParser

from stoq import helpers
from stoq.exceptions import StoqPluginException
from stoq import Payload, PayloadMeta, ArchiverResponse, StoqResponse, RequestMeta
from stoq.plugins import ProviderPlugin, ConnectorPlugin, ArchiverPlugin


class FileDirPlugin(ProviderPlugin, ConnectorPlugin, ArchiverPlugin):
    def __init__(self, config: ConfigParser, plugin_opts: Optional[Dict]) -> None:
        super().__init__(config, plugin_opts)

        self.source_dir = None
        self.recursive = False
        self.results_dir = os.path.join(os.getcwd(), 'results')
        self.date_mode = False
        self.date_format = '%Y/%m/%d'
        self.archive_dir = os.path.join(os.getcwd(), 'archive')
        self.use_sha = True
        self.compactly = True

        if plugin_opts and 'source_dir' in plugin_opts:
            self.source_dir = plugin_opts['source_dir']
        elif config.has_option('options', 'source_dir'):
            self.source_dir = config.get('options', 'source_dir')

        if plugin_opts and 'recursive' in plugin_opts:
            self.recursive = plugin_opts['recursive']
        elif config.has_option('options', 'recursive'):
            self.recursive = config.getboolean('options', 'recursive')

        if plugin_opts and 'results_dir' in plugin_opts:
            self.results_dir = plugin_opts['results_dir']
        elif config.has_option('options', 'results_dir'):
            self.results_dir = config.get('options', 'results_dir')

        if plugin_opts and 'date_mode' in plugin_opts:
            self.date_mode = plugin_opts['date_mode']
        elif config.has_option('options', 'date_mode'):
            self.date_mode = config.getboolean('options', 'date_mode')

        if plugin_opts and 'date_format' in plugin_opts:
            self.date_format = plugin_opts['date_format']
        elif config.has_option('options', 'date_format'):
            self.date_format = config.get('options', 'date_format')

        if plugin_opts and 'compactly' in plugin_opts:
            self.compactly = plugin_opts['compactly']
        elif config.has_option('options', 'compactly'):
            self.compactly = config.getboolean('options', 'compactly')

        if plugin_opts and 'archive_dir' in plugin_opts:
            self.archive_dir = plugin_opts['archive_dir']
        elif config.has_option('options', 'archive_dir'):
            self.archive_dir = config.get('options', 'archive_dir')

        if plugin_opts and 'use_sha' in plugin_opts:
            self.use_sha = plugin_opts['use_sha']
        elif config.has_option('options', 'use_sha'):
            self.use_sha = config.getboolean('options', 'use_sha')

    def ingest(self, queue: Queue) -> None:
        """
        Ingest files from a directory

        """
        if not self.source_dir:
            raise StoqPluginException('Source directory not defined')
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
            self._queue(self.source_dir, queue)

    def _queue(self, path: str, queue: Queue) -> None:
        """
        Publish payload to stoQ queue

        """
        meta = PayloadMeta(
            extra_data={
                'filename': os.path.basename(path),
                'source_dir': os.path.dirname(path),
            }
        )
        with open(path, "rb") as f:
            queue.put(Payload(f.read(), meta))

    def save(self, response: StoqResponse) -> None:
        """
        Save results to disk

        """

        path = self.results_dir
        filename = response.scan_id
        if self.date_mode:
            now = datetime.now().strftime(self.date_format)
            path = f'{path}/{now}'
        path = os.path.abspath(path)
        Path(path).mkdir(parents=True, exist_ok=True)
        with open(f'{path}/{filename}', 'x') as outfile:
            outfile.write(f'{helpers.dumps(response, compactly=self.compactly)}\n')

    def archive(self, payload: Payload, request_meta: RequestMeta) -> ArchiverResponse:
        """
        Archive payload to disk

        """
        path = self.archive_dir
        filename = payload.payload_id
        if self.use_sha:
            filename = hashlib.sha1(payload.content).hexdigest()
            path = f'{path}/{"/".join(list(filename[:5]))}'
        elif self.date_mode:
            now = datetime.now().strftime(self.date_format)
            path = f'{path}/{now}'
        path = os.path.abspath(path)
        Path(path).mkdir(parents=True, exist_ok=True)
        try:
            with open(f'{path}/{filename}', 'xb') as outfile:
                outfile.write(payload.content)
        except FileExistsError:
            pass
        return ArchiverResponse({'path': f'{path}/{filename}'})

    def get(self, task: ArchiverResponse) -> Payload:
        """
        Retrieve archived payload from disk

        """
        path = os.path.abspath(task.results['path'])
        meta = PayloadMeta(extra_data=task.results)
        with open(path, 'rb') as f:
            return Payload(f.read(), meta)
