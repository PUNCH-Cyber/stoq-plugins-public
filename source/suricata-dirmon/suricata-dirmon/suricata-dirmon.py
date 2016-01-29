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

Monitor a directory for files extracted by Suricata

"""

from time import sleep
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from stoq.plugins import StoqSourcePlugin


class SuricataDirmonSource(StoqSourcePlugin, FileSystemEventHandler):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):
        self.stoq = stoq
        super().activate()

    def on_created(self, event):

        # Skip this file if it is the meta file created by Suricata
        if event.src_path.endswith(".meta"):
            return

        # We should be left with only the file that was carved, time to
        # open the meta file, parse it, and make sure we pass the content
        # as metadata back into stoQ.
        meta = {}

        # Make sure we define the filename is correctly
        meta_filename = "{}.meta".format(event.src_path)

        content = self.stoq.get_file(meta_filename)

        # Normalize the metadata content so we can store is in a dict
        for line in content.splitlines():
            meta_line = line.split(b':', 1)

            # Normalize the key
            meta_key = meta_line[0].decode()
            meta_key = meta_key.lower()
            meta_key = meta_key.replace(" ", "_")

            meta_value = meta_line[1].strip()

            meta[meta_key] = meta_value

        self.stoq.worker.multiprocess_put(path=event.src_path, archive='file', **meta)

    def ingest(self):
        """
        Monitor a directory for files extracted by Suricata

        """

        observer = Observer()
        observer.schedule(self, self.stoq.worker.path, recursive=False)
        observer.start()
        self.stoq.log.info("Monitoring {} for extracted files...".format(
                           self.stoq.worker.path))
        try:
            while True:
                sleep(2)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()

