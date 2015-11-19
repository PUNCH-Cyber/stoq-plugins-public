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

Carve hex/binary streams from RTF payloads

"""

import re
import binascii

from io import BytesIO

from stoq.plugins import StoqCarverPlugin


class RTFCarver(StoqCarverPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):
        self.stoq = stoq

        super().activate()

        # Make sure these are bytes
        self.headers = self.headers.encode()

    def carve(self, payload, **kwargs):
        """
        Carve hex/binary streams from RTF payloads

        :param bytes payload: RTF Payload to be parsed
        :param **kwargs kwargs: Additional attributes (unused)

        :returns: Extracted binary streams
        :rtype: list of tuples

        """

        results = None

        payload = BytesIO(payload)
        payload.seek(0)

        magic = payload.read(2).decode()
        payload.seek(0)

        # Does not appear to be a valid RTF file
        if not magic.startswith("{\\"):
            return None

        for start, end in self.carve_payload(self.headers, payload, ignorecase=True):
            payload.seek(start)

            # Calculate the size of the content
            content_size = end - start

            # Skip this one if the content size is less than or
            # equal to 8 bytes
            if content_size <= int(self.minimum_size):
                continue

            # Read the full content
            content = payload.read(content_size)

            # Remove any newlines
            content = re.sub(r'(\r|\n)', '', content.decode())

            if not results:
                results = list()

            try:
                # Convert the hex into binary
                content = binascii.unhexlify(content)
            except:
                continue

            # Gather meta data and content
            meta = {"offset": start, "size": content_size}
            results.append((meta, content))

            self.stoq.log.info("Carved binary stream in RTF at offset {} ({} bytes)".format(start, content_size))

        return results

