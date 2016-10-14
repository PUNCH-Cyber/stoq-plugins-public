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

Process a payload using yara

"""

import os
import time
import argparse
import threading
import yara
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from stoq.args import StoqArgs
from stoq.plugins import StoqWorkerPlugin


class YaraScan(StoqWorkerPlugin, FileSystemEventHandler):

    def __init__(self):
        super().__init__()
        self.rule_lock = threading.Lock()
        self.wants_heartbeat = True

    def activate(self, stoq):

        self.stoq = stoq

        parser = argparse.ArgumentParser()
        parser = StoqArgs(parser)
        worker_opts = parser.add_argument_group("Plugin Options")
        worker_opts.add_argument("-r", "--yararules",
                                 dest='yararules',
                                 help="Path to yara rules file")

        options = parser.parse_args(self.stoq.argv[2:])

        super().activate(options=options)

        # Make sure we compile our rules when activated.
        self._load_yara_rules()

        return True

    def scan(self, payload, **kwargs):
        """
        Scan a payload using yara

        :param bytes payload: Payload to be scanned
        :param **kwargs kwargs: Additional parameters (unused)

        :returns: Results from scan
        :rtype: dict or None

        """

        # Define our required variables
        self.results = []

        # Scan the payload with a timeout using yara
        self.rule_lock.acquire()
        self.rules.match(data=payload, timeout=60,
                         callback=self._scan_callback)
        self.rule_lock.release()
        super().scan()

        # Return our results
        if self.results:
            return self.results
        else:
            return None

    # If the rules file is modified, we are going to reload the rules.
    def on_modified(self, event):
        self.log.debug("Yara rule {0} modified".format(event.src_path))
        self._load_yara_rules()

    def _scan_callback(self, data):
        if data['matches']:
            # We want to make sure the offset is a str rather than int
            # so our output plays nicely. For instance, if we do not
            # do this, elasticsearch will assume that all objects in the
            # set are ints rather than a mix of int and str.
            strings = []
            for key in data['strings']:
                hit = (str(key[0]), key[1], key[2])
                strings.append(hit)
            data['strings'] = strings
            self.results.append(data)
        yara.CALLBACK_CONTINUE

    def _load_yara_rules(self):
        try:
            self.log.debug("Loading yara rules.")
            # We don't want to name our rules globally just yet, in case
            # loading fails.
            self.rule_lock.acquire()
            compiled_rules = yara.compile(self.yararules)
            self.rules = compiled_rules
            self.rule_lock.release()
        except Exception:
            self.log.critical("Error in yara rules. Compile failed.", exc_info=True)
            # If this is the first time we are loading the rules,
            # we are going to exit here.
            if not hasattr(self, 'rules'):
                exit(-1)

    def heartbeat(self):
        # Get the full absolute path of the yara rules directory
        yara_rules_base = os.path.dirname(os.path.abspath(self.yararules))

        # Instantiate our observer.
        observer = Observer()
        observer.schedule(self, yara_rules_base, recursive=True)
        observer.start()
        try:
            while True:
                time.sleep(5)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()
