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

Carve portable executable files from a data stream

"""

import pefile

from io import BytesIO

from stoq.plugins import StoqCarverPlugin


class PECarver(StoqCarverPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):
        self.stoq = stoq

        super().activate()

        # Make sure these are bytes
        self.headers = self.headers.encode()

    def carve(self, payload, **kwargs):
        """
        Carve PE files from provided payload

        :param bytes payload: Payload to be parsed
        :param **kwargs kwargs: Additional attributes (unused)

        :returns: Extracted files
        :rtype: list of tuples

        """

        results = None

        payload = BytesIO(payload)
        payload.seek(0)

        for start, end in self.carve_payload(self.headers, payload):
            payload.seek(start)

            # Attempt to load the carved file using pefile,
            # continue on to the next index if it fails
            try:
                pe = pefile.PE(data=payload.read())
            except:
                continue

            binary = pe.trim()

            # If results are None, let's ensure it is a list
            # so we can store our result set()
            if not results:
                results = list()

            # Generate the metadata and the binary carved
            meta = {'offset': start, 'size': len(binary)}
            results.append((meta, pe.trim()))

            self.stoq.log.info("Carved executable at offset {} ({} bytes)".format(meta['offset'],
                                                                                  meta['size']))

            # Start all over
            payload.seek(0)
            pe.close()

        return results
