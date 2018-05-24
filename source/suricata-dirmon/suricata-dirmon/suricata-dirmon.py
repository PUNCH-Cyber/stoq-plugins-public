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

import os

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

        # Skip this file if it is not the meta file created by Suricata
        if not event.src_path.endswith(".meta") or not event.src_path.endswith(".meta.tmp"):
            return

        # A bit of a race condition here. Suricata writes a tmp file, until the stream is complete.
        # At that point, suricata moves file to a filename minus the .tmp extension which is not
        # detected by the filesystem as an on_created() event, thus we will never see it. Let's
        # assume that if the file name ends with a ".tmp" extension, by the time we get to loading
        # the file itself, suricata has finished writing to disk. Ugly? yes.
        if event.src_path.endswith(".tmp"):
            meta_filename = os.path.splitext(event.src_path)[0]
        else:
            meta_filename = event.src_path

        # We should be left with only the file that was carved, time to
        # open the meta file, parse it, and make sure we pass the content
        # as metadata back into stoQ.
        meta = {}

        # Make sure we define the filename correctly
        path = os.path.splitext(meta_filename)[0]

        content = self.stoq.get_file(meta_filename)

        # Normalize the metadata content so we can store is in a dict
        for line in content.splitlines():
            meta_line = line.split(b':', 1)

            # Normalize the key
            meta_key = meta_line[0].decode()
            meta_key = meta_key.lower()
            meta_key = meta_key.replace(" ", "_")

            # Attempt to decode the value of the key, if we can't due to the
            # encoding, we will leave it as bytes().
            try:
                meta_value = meta_line[1].strip().decode()
            except UnicodeDecodeError:
                meta_value = meta_line[1].strip()

            meta[meta_key] = meta_value

        meta['src'] = 'suricata'

        self.stoq.worker.multiprocess_put(path=path, archive='file', **meta)

    def ingest(self):
        """
        Monitor a directory for files extracted by Suricata

        """

        observer = Observer()
        observer.schedule(self, self.stoq.worker.path, recursive=False)
        observer.start()
        self.log.info("Monitoring {} for extracted files...".format(self.stoq.worker.path))

        try:
            while True:
                sleep(2)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()
