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

Identify file types from their TrID signature

"""

import os
import argparse
from subprocess import check_output

from stoq.args import StoqArgs
from stoq.plugins import StoqWorkerPlugin


class TridScan(StoqWorkerPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):

        self.stoq = stoq

        parser = argparse.ArgumentParser()
        parser = StoqArgs(parser)

        worker_opts = parser.add_argument_group("Plugin Options")
        worker_opts.add_argument("--defs",
                                 dest='defs',
                                 help="Path to definition database")

        options = parser.parse_args(self.stoq.argv[2:])

        super().activate(options=options)

        return True

    def scan(self, payload, **kwargs):
        """
        Scan a payload using TRiD

        :param bytes payload: Payload to be scanned
        :param **kwargs kwargs: Additional parameters (unused)

        :returns: Results from scan
        :rtype: dict or None

        """

        results = []
        start_pos = 6

        path = self.stoq.write(path=self.stoq.temp_dir,
                               payload=payload,
                               binary=True)

        if not os.path.isfile(self.bin):
            self.log.error("TrID does not exist at {}!".format(self.bin))
            return None

        # Build our command and then execute it
        cmd = [self.bin, "-d:{}".format(self.defs), path]
        trid_results = check_output(cmd).splitlines()

        # If there are results, iterate over them and build our blob
        if len(trid_results) > 0:
            try:
                if trid_results[7].startswith("Warning".encode()):
                    start_pos = 10
            except IndexError:
                pass

            for line in trid_results[start_pos:]:
                line = line.decode().split()
                r = {}
                if len(line) > 1:
                    r['likely'] = line[0]
                    r['extension'] = line[1]
                    r['type'] = ' '.join(line[2:])
                else:
                    r['likely'] = "Unk"
                    r['extension'] = "Unk"
                    r['type'] = "Unk"
                results.append(r)

        # Time to cleanup if we wrote a temp file to disk
        try:
            if os.isfile(path):
                os.remove(path)
        except:
            pass

        super().scan()

        if results:
            return results
        else:
            return None
