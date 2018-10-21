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

Monitor a directory for newly created files for processing

"""

import os
from time import sleep
from queue import Queue
from typing import Dict, Optional
from configparser import ConfigParser
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from stoq.plugins import ProviderPlugin
from stoq import Payload, PayloadMeta


class DirmonPlugin(ProviderPlugin):
    def __init__(self, config: ConfigParser, plugin_opts: Optional[Dict]) -> None:
        super().__init__(config, plugin_opts)

        if plugin_opts and 'source_dir' in plugin_opts:
            self.source_dir = plugin_opts['source_dir']
        elif config.has_option('options', 'source_dir'):
            self.source_dir = config.get('options', 'source_dir')
        else:
            self.source_dir = None

        if not self.source_dir:
            raise StoqException('Source directory not defined')

    def ingest(self, queue: Queue) -> None:
        """
        Monitor a directory for newly created files for ingest

        """

        handler = WatchdogEvent(queue)
        observer = Observer()
        observer.schedule(handler, self.source_dir, recursive=False)
        observer.start()
        try:
            while True:
                sleep(2)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()


class WatchdogEvent(FileSystemEventHandler):
    def __init__(self, queue: Queue) -> None:
        self.queue = queue

    def on_created(self, event):
        meta = PayloadMeta(
            extra_data={
                'filename': os.path.basename(event.src_path),
                'source_dir': os.path.dirname(event.src_path),
            }
        )
        with open(event.src_path, "rb") as f:
            self.queue.put(Payload(f.read(), meta))
