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

Carve OLE Package Streams

.. note:: This plugin is based on psparser.py by Sean Wilson of PhishMe

"""

import struct

from io import BytesIO
from binascii import hexlify

from stoq.plugins import StoqCarverPlugin


class OLEPackageStreamCarver(StoqCarverPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):
        self.stoq = stoq

        super().activate()

    def carve(self, payload, **kwargs):
        """
        Carve OLE streams

        :param bytes payload: OLE Package Stream
        :param **kwargs kwargs: Additional attributes (unused)

        :returns: Carved OLE Package Streams
        :rtype: list of tuples

        """

        try:
            payload = BytesIO(payload)
            return self.parse_stream(payload)
        except:
            return None

    def split_null(self, payload):
        pos = payload.tell()
        # Grab everything between the last byte and the next null byte
        data = payload.read().split(b'\x00')[0]

        # Skip over the null byte
        offset = len(data) + pos + 1

        return data.decode(), offset

    def parse_stream(self, payload):
        meta = {}

        payload.seek(4)

        meta['Header'] = hexlify(payload.read(2)).decode()

        meta['Label'], offset = self.split_null(payload)
        payload.seek(offset)

        meta['OriginalPath'], offset = self.split_null(payload)
        payload.seek(offset)

        meta['FormatId'] = hexlify(payload.read(4)).decode()

        meta['DefaultExtractPathLength'] = struct.unpack('<i', payload.read(4))[0]

        meta['DefaultExtractPath'], offset = self.split_null(payload)
        payload.seek(offset)

        meta['size'] = struct.unpack('<i', payload.read(4))[0]

        stream_buffer = payload.read(meta['size'])

        meta['DefaultExtractPathWLength'] = struct.unpack('<i', payload.read(4))[0]

        meta['DefaultExtractPathW'] = hexlify(payload.read(meta['DefaultExtractPathWLength'] * 2)).decode()

        meta['LabelWLength'] = struct.unpack('<i', payload.read(4))[0]

        meta['LabelW'] = hexlify(payload.read(meta['LabelWLength'] * 2)).decode()

        meta['OrgFileWLength'] = struct.unpack('<i', payload.read(4))[0]

        meta['OrgFileW'] = hexlify(payload.read(meta['OrgFileWLength'] * 2)).decode()

        self.log.info("Carved OLE Package Stream {} ({} bytes)".format(meta['DefaultExtractPath'],
                                                                       meta['size']))

        return [(meta, stream_buffer)]
