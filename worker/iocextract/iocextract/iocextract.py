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

Utilizes reader/iocregex plugin to extract indicators of compromise
from documents

"""

import argparse

from stoq.args import StoqArgs
from stoq.plugins import StoqWorkerPlugin


class IOCExtract(StoqWorkerPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):
        self.stoq = stoq

        parser = argparse.ArgumentParser()
        parser = StoqArgs(parser)
        worker_opts = parser.add_argument_group("Plugin Options")
        worker_opts.add_argument("-p", "--password",
                                 dest='password',
                                 default=False,
                                 help="Password for encrypted file")
        worker_opts.add_argument("-t", "--force-tika",
                                 dest='force_tika',
                                 action='store_false',
                                 help="Force the use of tika for all files")

        options = parser.parse_args(self.stoq.argv[2:])

        super().activate(options=options)

        self.load_reader('iocregex')

        return True

    def scan(self, payload, **kwargs):
        """
        Extract IOC's from a payload

        :param bytes payload: Payload to be scanned
        :param **kwargs kwargs: Additional parameters (unused)

        :returns: Results from scan
        :rtype: dict or None

        """

        super().scan()

        results = {}

        # This is sloppy logic for now, but we can improve later. We are going
        # to check for a PDF header, if it is there, let's use our pdftext
        # plugin.
        if payload[0:5] == b'%PDF-' and not self.force_tika:
            self.load_reader('pdftext')
            results = self.readers['pdftext'].read(payload)
        else:
            try:
                self.load_reader('tika')
                # Send the content of our payload to the tika server
                results = self.readers['tika'].read(payload)
            except:
                self.stoq.log.warn("Extraction with Tika failed. Reverting to ASCII strings.")
                results = self.stoq.force_unicode(payload)

        if results:
            # Extract and return any indicators from the extracted text
            return self.readers['iocregex'].read(results)
        else:
            return None
