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
