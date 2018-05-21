#   Copyright 2014-2018 PUNCH Cyber Analytics Group
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

Parse and abstract PE, ELF and MachO files using LIEF

"""

import os
import argparse
import lief

from stoq.args import StoqArgs
from stoq.plugins import StoqWorkerPlugin


class LiefScan(StoqWorkerPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):

        self.stoq = stoq

        parser = argparse.ArgumentParser()
        parser = StoqArgs(parser)
        worker_opts = parser.add_argument_group("Plugin Options")
        worker_opts.add_argument("--dont-abstract",
                                 dest='abstract',
                                 default=None,
                                 action='store_false',
                                 help="Don't output the  abstracted information")

        options = parser.parse_args(self.stoq.argv[2:])

        super().activate(options=options)

        return True

    def scan(self, payload, **kwargs):
        """
        Scan a payload using LIEF

        :param bytes payload: Payload to be scanned
        :param **kwargs filename: Filename of the file to scan
        :param **kwargs path: Path of the file to scan
        :returns: Results from scan
        :rtype: dict or None

        """

        super().scan()

        if 'filename' in kwargs:
            filename = kwargs.pop('filename')
        elif 'path' in kwargs:
            filename = os.path.basename(kwargs.pop('path'))
        else:
            filename = 'unknown'

        self.lief_open(payload, filename)

        if self.binary:
            if self.abstract:
                results = lief.abstract_to_json(self.binary)
            else:
                results = lief.to_json(self.binary)

            return self.stoq.loads(results)

        # Not any of the supported file formats, return none
        return None

    def lief_open(self, payload, filename):
        """
        Open a binary using LIEF
        """

        data = list(payload)

        try:
            self.binary = lief.parse(payload, filename)
        except (lief.bad_format, lief.bad_file) as err:
            self.log.debug(err)
            self.binary = None
