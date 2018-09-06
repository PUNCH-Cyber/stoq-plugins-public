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

Carve and decompress SWF payloads

"""

import zlib
import pylzma
import struct

from io import BytesIO

from stoq.plugins import StoqCarverPlugin


class SWFCarver(StoqCarverPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):
        self.stoq = stoq

        super().activate()

        # Make sure these are bytes
        self.headers = self.headers.encode()

    def carve(self, payload, **kwargs):
        """
        Carve and decompress SWF streams

        :param bytes payload: Payload with SWF to be decompressed
        :param **kwargs kwargs: Additional attributes (unused)

        :returns: Decompressed SWF streams
        :rtype: list of tuples

        """

        results = None

        # Let's make this a file object to simplify our seeks
        payload = BytesIO(payload)
        payload.seek(0)

        for start, end in self.carve_payload(self.headers, payload):
            swf = self.decompress(payload, start)
            if swf:
                # If results are None, let's ensure it is a list
                # so we can store our result set()
                if not results:
                    results = []

                results.append(swf)

        return results

    def decompress(self, payload, offset=0):
        try:
            ##
            # Header as obtained from SWF File Specification:
            # Field Type Comment
            # Signature UI8 Signature byte:
            #     “F” indicates uncompressed
            #     “C” indicates a zlib compressed SWF (SWF 6
            #         and later only)
            #     “Z” indicates a LZMA compressed SWF (SWF
            #         13 and later only)
            #
            # Signature UI8 Signature byte always “W”
            #
            # Signature UI8 Signature byte always “S”
            #
            # Version UI8 Single byte file version (for example, 0x06 for
            # SWF 6)
            #
            # FileLength UI32 Length of entire file in bytes
            ##

            # Jump to the proper offset
            payload.seek(offset)

            # Grab the first three bytes, should be FWS, CWS or ZWS
            magic = payload.read(3).decode()

            # Grab the SWF version - 1 byte
            swf_version = struct.unpack('<b', payload.read(1))[0]

            # Grab next 4 bytes so we can unpack to calculate the uncompressed
            # size of the payload.
            decompressed_size = struct.unpack("<i", payload.read(4))[0] - 8

            # Let's go back to the offset byte, jumping beyond the SWF header
            payload.seek(offset+3)

            # Make sure our header is that of a decompressed SWF plus the
            # original version and size headers
            composite_header = b'FWS' + payload.read(5)

            # Determine the compression type, ZLIB or LZMA, then decompress the
            # payload size minus 8 bytes of original header
            try:
                if magic == "ZWS":
                    payload.seek(12)
                    content = pylzma.decompress(payload.read(decompressed_size))
                elif magic == "CWS":
                    content = zlib.decompress(payload.read(decompressed_size))
                elif magic == 'FWS':
                    # Not compressed, but let's return the payload based on the
                    # size defined in the header
                    content = payload.read(decompressed_size)
                else:
                    return None
            except:
                return None

            if len(content) != decompressed_size:
                raise(InvalidSWFSize)

            swf = composite_header + content

            meta = {'offset': offset,
                    'swf_version': swf_version,
                    'size': decompressed_size + 8
                    }

            self.log.info("Carved SWF at offset {} ({} bytes)".format(meta['offset'],
                                                                           meta['size']))
            return (meta, swf)

        except:
            self.log.warn("Unable to decompress SWF payload at offset {}".format(offset))
            return None


class InvalidSWFSize(Exception):
    """ Invalid size of carved SWF content """
    pass
