#   Copyright 2014-2016 PUNCH Cyber Analytics Group
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

Interact with ThreatGrid API

"""

import argparse
import pythreatgrid
import threading

from stoq.args import StoqArgs
from stoq.plugins import StoqWorkerPlugin
from time import sleep


class ThreatGridWorker(StoqWorkerPlugin):

    def __init__(self):
        super().__init__()
        self.threadgrid_lock = threading.Lock()

    def activate(self, stoq):
        self.stoq = stoq

        parser = argparse.ArgumentParser()
        parser = StoqArgs(parser)

        worker_opts = parser.add_argument_group("Plugin Options")
        worker_opts.add_argument("--api_host",
                                 dest='api_host',
                                 help="ThreatGrid API host")
        worker_opts.add_argument("--vm",
                                 dest='vm',
                                 default=None,
                                 help="Specified virtual machine to use")
        worker_opts.add_argument("--private",
                                 dest='private',
                                 default='false',
                                 help="Specify if sample should be marked private or not")
        worker_opts.add_argument("--api_key",
                                 dest='api_key',
                                 help="ThreatGrid API Key")
        worker_opts.add_argument("--tags",
                                 dest='tags',
                                 default=[],
                                 help="Tags applied to samples")
        worker_opts.add_argument("--playbook",
                                 dest='tags',
                                 default='none',
                                 help="Name of playbook to apply to sample run")
        worker_opts.add_argument("--network_exit",
                                 dest='network_exit',
                                 default='phl-ven',
                                 help="ThreatGrid network exit to use")

        options = parser.parse_args(self.stoq.argv[2:])
        super().activate(options=options)

        return True

    def scan(self, payload, **kwargs):
        """
        Scans a file using ThreatGrid API

        :param bytes payload: Payload to be scanned
        :param **kwargs kwargs: ThreatGrid API options
        :returns: Results from scan
        :rtype: dict or None
        """

        # Define our required variables
        results = {}

        # Scan the payload with a timeout using ThreatGrid
        self.threadgrid_lock.acquire()

        # Instantiate our API worker
        tg = pythreatgrid.ThreatGrid(api_host=self.api_host,
                                     vm=self.vm,
                                     filename=kwargs['filename'],
                                     private=self.private,
                                     api_key=self.api_key,
                                     tags=self.tags,
                                     playbook=self.playbook,
                                     network_exit=self.network_exit)

        # Submit payload to ThreatGrid API
        res = tg.submit_sample(payload)
        sample_id = res['data']['id']

        # Block while we wait for our scan to be successful
        while True:
            state = tg.get_samples_id_state(sample_id)
            # Check if ThreatGrid is still processing our file
            if state['data']['state'] == 'succ':
                results = tg.get_samples_id_analysis(sample_id)
                break
            if state['data']['state'] == 'fail':
                self.log.error("Error: sample analysis failed")
                results = {}
                break
            sleep(60)

        self.threadgrid_lock.release()
        super().scan()

        # Return our results
        if results:
            return results
        else:
            return None
