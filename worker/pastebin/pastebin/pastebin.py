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

Scrape Pastebin content

"""

import argparse

from stoq.args import StoqArgs
from stoq.plugins import StoqWorkerPlugin


class PastebinScan(StoqWorkerPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):
        self.stoq = stoq
        parser = argparse.ArgumentParser()
        parser = StoqArgs(parser)

        worker_opts = parser.add_argument_group("Plugin Options")
        worker_opts.add_argument("-l", "--limit",
                                 dest='limit',
                                 help="Maximum number of results to return")

        options = parser.parse_args(self.stoq.argv[2:])

        super().activate(options=options)

        # We want to save each result individually, so let's save the output
        # when we scan it rather than having the framework handle it
        self.load_connector(self.output_connector)

        return True

    def scan(self, payload=None, **kwargs):
        """
        Interact with Censys API

        :param None payload: Unused
        :param str limit: Maximum number of results to return

        :returns: True

        """

        limit = kwargs.get('limit', self.limit)

        params = {'limit': limit}

        pastes = self.stoq.get_file(self.url, params)
        pastes = self.stoq.loads(pastes)

        try:
            with open(self.tracker, "r") as tracker:
                epoch = int(tracker.read())
        except (FileNotFoundError, ValueError):
            epoch = 0

        # Make sure we track the epochs so we know where we left off
        paste_dates = [epoch]

        for paste in pastes:
            paste_date =  int(paste['date'])
            if epoch < paste_date:
                paste_dates.append(paste_date)
                try:
                    paste['content'] = self.stoq.get_file(paste['scrape_url'])
                except:
                    paste['content'] = "ERR"

                self.connectors[self.output_connector].save(paste)

        # Write the latest epoch to the tracker file
        with open(self.tracker, "w") as tracker:
            tracker.write(str(max(paste_dates)))

        return True
