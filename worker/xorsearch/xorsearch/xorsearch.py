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

Search a payload for XOR'd strings

"""

import os
import sys
import argparse
from subprocess import check_output

from stoq.args import StoqArgs
from stoq.plugins import StoqWorkerPlugin


class XorSearchScan(StoqWorkerPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):

        self.stoq = stoq

        parser = argparse.ArgumentParser()
        parser = StoqArgs(parser)

        worker_opts = parser.add_argument_group("Plugin Options")
        worker_opts.add_argument("-x", "--xorsearch",
                                 dest='bin',
                                 help="Filename to scan")
        worker_opts.add_argument("--terms",
                                 dest='terms',
                                 help="Path to the xorsearch terms file")

        options = parser.parse_args(sys.argv[2:])
        super().activate(options=options)

        return True

    def scan(self, payload, **kwargs):
        """
        Scan a payload using XORSearch

        :param bytes payload: Payload to be scanned
        :param **kwargs kwargs: Additional parameters (unused)

        :returns: Results from scan
        :rtype: dict or None

        """

        results = {}
        hits = []

        path = self.stoq.write(path=self.stoq.temp_dir,
                               payload=payload,
                               binary=True)

        if not os.path.isfile(self.bin):
            self.stoq.log.error("XORSearch does not exist at {}!".format(self.bin))
            return None

        # Build our command and then execute it
        cmd = [self.bin, '-f', self.terms, path]
        process_results = check_output(cmd).splitlines()

        # If there are results, iterate over them and build our blob
        if len(process_results) > 0:
            for line in process_results:
                line = line.decode()
                result = line.split()
                hit = line.split(': ')
                r = {}
                # We are going to skip over hits that are not xor'd
                if result[2] != '00':
                    r['xor'] = result[2]
                    r['pos'] = result[4].replace(':', '')
                    r['str'] = hit[1]
                    hits.append(r)

        results['hits'] = hits

        # Time to cleanup if we wrote a temp file to disk
        try:
            if os.isfile(path):
                os.remove(path)
        except:
            pass

        super().scan()

        return results
