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

from time import sleep
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from stoq.plugins import StoqSourcePlugin


class DirmonSource(StoqSourcePlugin, FileSystemEventHandler):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):
        self.stoq = stoq
        super().activate()

    # When a file is created, let's pass the file path to our predefined worker
    def on_created(self, event):
        self.stoq.worker.multiprocess_put(path=event.src_path, archive='file')

    def ingest(self):
        """
        Monitor a directory for newly created files for ingest

        """

        observer = Observer()
        observer.schedule(self, self.stoq.worker.path, recursive=False)
        observer.start()
        self.log.info("Monitoring {} for new files...".format(
                      self.stoq.worker.path))
        try:
            while True:
                sleep(2)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()
