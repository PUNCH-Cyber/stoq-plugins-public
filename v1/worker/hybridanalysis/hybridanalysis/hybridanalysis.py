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
Retrieve public feed data from Hybrid Analysis
"""
import argparse

from stoq.args import StoqArgs
from stoq.plugins import StoqWorkerPlugin


class HybridAnalysis(StoqWorkerPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):
        self.stoq = stoq

        parser = argparse.ArgumentParser()
        parser = StoqArgs(parser)
        options = parser.parse_args(self.stoq.argv[2:])

        super().activate(options=options)

    def scan(self, payload=None, **kwargs):
        super().scan()
        url = "https://www.hybrid-analysis.com/feed?json"
        raw_results = self.stoq.get_file(url)
        scan_results = self.stoq.loads(raw_results)

        if scan_results['data']:
            return scan_results['data']

        return None
