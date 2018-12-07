#!/usr/bin/env python3

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

Carve and decompress SWF files from payloads

"""

import re
import zlib
import pylzma
import struct
from io import BytesIO
from typing import Dict, Optional
from configparser import ConfigParser

from stoq.plugins import WorkerPlugin
from stoq import Payload, PayloadMeta, ExtractedPayload, RequestMeta, WorkerResponse


class PeCarve(WorkerPlugin):
    def __init__(self, config: ConfigParser, plugin_opts: Optional[Dict]) -> None:
        super().__init__(config, plugin_opts)

        if plugin_opts and 'swf_headers' in plugin_opts:
            self.swf_headers = plugin_opts['swf_headers'].encode()
        elif config.has_option('options', 'swf_headers'):
            self.swf_headers = config.get('options', 'swf_headers').encode()

    def scan(self, payload: Payload, request_meta: RequestMeta) -> WorkerResponse:
        """
        Carve and decompress SWF files from payloads

        """

        extracted = []
        errors = []
        content = BytesIO(payload.content)
        content.seek(0)
        for start, end in self._carve(content):
            ex, err = self.decompress(content, start)
            if ex:
                extracted.append(ex)
            if err:
                errors.extend(err)
        return WorkerResponse(extracted=extracted, errors=errors)

    def decompress(self, content: BytesIO, offset: int = 0):
        """
        Extract and decompress an SWF object

        """
        errors = []
        meta = None
        swf = None
        try:
            """
            Header as obtained from SWF File Specification:
            Field Type Comment
            Signature UI8 Signature byte:
                - “F” indicates uncompressed
                - “C” indicates a zlib compressed SWF (SWF 6 and later only)
                - “Z” indicates a LZMA compressed SWF (SWF 13 and later only)
            - Signature UI8 Signature byte always “W”
            - Signature UI8 Signature byte always “S”
            - Version UI8 Single byte file version (for example, 0x06 for SWF 6)
            - FileLength UI32 Length of entire file in bytes
            """
            # Jump to the proper offset
            content.seek(offset)
            # Grab the first three bytes, should be FWS, CWS or ZWS
            magic = content.read(3).decode()
            # Grab the SWF version - 1 byte
            swf_version = struct.unpack('<b', content.read(1))[0]
            # Grab next 4 bytes so we can unpack to calculate the uncompressed
            # size of the payload.
            decompressed_size = struct.unpack("<i", content.read(4))[0] - 8
            # Let's go back to the offset byte, jumping beyond the SWF header
            content.seek(offset + 3)
            # Make sure our header is that of a decompressed SWF plus the
            # original version and size headers
            composite_header = b'FWS' + content.read(5)
            # Determine the compression type, ZLIB or LZMA, then decompress the
            # payload size minus 8 bytes of original header
            try:
                if magic == "ZWS":
                    content.seek(12)
                    content = pylzma.decompress(content.read(decompressed_size))
                elif magic == "CWS":
                    content = zlib.decompress(content.read(decompressed_size))
                elif magic == 'FWS':
                    # Not compressed, but let's return the payload based on the
                    # size defined in the header
                    content = content.read(decompressed_size)
                else:
                    return None, errors
            except:
                return None, errors

            if len(content) != decompressed_size:
                errors.append(
                    'Invalid size of carved SWF content: {len(content)} != {decompressed_size}'
                )
            else:
                swf = composite_header + content
                meta = PayloadMeta(
                    extra_data={'offset': offset, 'swf_version': swf_version}
                )
                extracted = ExtractedPayload(swf, meta)
        except:
            errors.append(f'Unable to decompress SWF payload at offset {offset}')
        return extracted, errors

    def _carve(self, content: BytesIO):
        """
        Generator that returns a list of offsets for a specified value
        within a payload

        """
        for buff in re.finditer(self.swf_headers, content.read(), re.M | re.S):
            yield buff.start(), buff.end()
