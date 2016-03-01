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

Carve OLE Package Streams within Microsoft Office Documents

.. note:: This plugin is based on psparser.py by Sean Wilson of PhishMe

"""

import struct
from binascii import unhexlify, hexlify

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

        :param str payload: Hex encoded str of the OLE Package Stream
        :param **kwargs kwargs: Additional attributes (unused)

        :returns: Carved OLE Package Streams
        :rtype: list of tuples

        """

        #try:
        payload = hexlify(payload[4:]).decode()
        return self._parse_stream(payload)
        # except:
            # return None

    def _processvalue(self, value):
        try:
            return unhexlify(value).decode()
        except AttributeError:
            return value
        except TypeError:
            return value

    def _getvarstring(self, payload, position):
        return_string = ''
        curpos = position
        endpos = 0
        while True:
            if payload[curpos:curpos+2] == '00':
                endpos = curpos+2
                break
            return_string += payload[curpos:curpos+2]
            curpos += 2
        return_string = self._processvalue(return_string)
        return return_string, endpos

    def _parse_stream(self, payload):
        meta = {}

        curpos = 0

        meta['Header'] = payload[curpos:curpos+4]
        curpos += 4

        meta['Label'], curpos = self._getvarstring(payload, curpos)

        meta['OriginalPath'], curpos = self._getvarstring(payload, curpos)

        meta['FormatId'] = payload[curpos:curpos+8]
        curpos += 8

        meta['DefaultExtractPathLength'] = struct.unpack('<i', bytearray.fromhex(payload[curpos:curpos+8]))[0]
        curpos += 8

        meta['DefaultExtractPath'], curpos = self._getvarstring(payload, curpos)

        meta['size'] = struct.unpack('<i', bytearray.fromhex(payload[curpos:curpos+8]))[0]
        curpos += 8

        stream_buffer = unhexlify(payload[curpos:curpos + (meta['size'] * 2)])
        curpos += (meta['size'] * 2)

        meta['DefaultExtractPathWLength'] = struct.unpack('<i', bytearray.fromhex(payload[curpos:curpos+8]))[0]
        curpos += 8

        meta['DefaultExtractPathW'] = payload[curpos:curpos + (meta['DefaultExtractPathWLength'] * 4)]
        curpos += (meta['DefaultExtractPathWLength'] * 4)

        meta['LabelWLength'] = struct.unpack('<i', bytearray.fromhex(payload[curpos:curpos+8]))[0]
        curpos += 8

        meta['LabelW'] = payload[curpos:curpos+(meta['LabelWLength'] * 4)]
        curpos += (meta['LabelWLength'] * 4)

        meta['OrgFileWLength'] = struct.unpack('<i', bytearray.fromhex(payload[curpos:curpos+8]))[0]
        curpos += 8

        meta['OrgFileW'] = payload[curpos:curpos+(meta['OrgFileWLength'] * 4)]
        curpos += (meta['OrgFileWLength'] * 4)

        self.stoq.log.info("Carved OLE Package Stream {} ({} bytes)".format(meta['DefaultExtractPath'],
                                                                            meta['size']))
 
        return [(meta, stream_buffer)]
