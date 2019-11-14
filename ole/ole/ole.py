#!/usr/bin/env python3

#   Copyright 2014-present PUNCH Cyber Analytics Group
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

Carve OLE streams within Microsoft Office Documents

"""

import string
import olefile
from oletools import oleobj

from stoq.plugins import WorkerPlugin
from stoq import Error, Payload, PayloadMeta, ExtractedPayload, Request, WorkerResponse


class OlePlugin(WorkerPlugin):
    async def scan(self, payload: Payload, request: Request) -> WorkerResponse:
        extracted = []
        ole_object = olefile.OleFileIO(payload.content)
        streams = ole_object.listdir(streams=True)
        for stream in streams:
            try:
                stream_buffer = ole_object.openstream(stream).read()
                name = ''.join(
                    filter(lambda x: x in string.printable, '_'.join(stream))
                )
                if stream_buffer.endswith(b'\x01Ole10Native'):
                    ole_native = oleobj.OleNativeStream(stream_buffer)
                    if ole_native.filename:
                        name = f'{name}_{str(ole_native.filename)}'
                    else:
                        name = f'{name}_olenative'
                    meta = PayloadMeta(
                        should_archive=False,
                        extra_data={'index': streams.index(stream), 'name': name},
                    )
                    extracted.append(ExtractedPayload(ole_native.data, meta))
                else:
                    meta = PayloadMeta(
                        should_archive=False,
                        extra_data={'index': streams.index(stream), 'name': name},
                    )
                    extracted.append(ExtractedPayload(stream_buffer, meta))
            except Exception as err:
                request.errors.append(
                    Error(
                        error=str(err),
                        plugin_name=self.plugin_name,
                        payload_id=payload.payload_id,
                    )
                )
        return WorkerResponse(extracted=extracted)
