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

Carve OLE streams within Microsoft Office Documents

"""

import string
import olefile
from oletools import oleobj

from stoq.plugins import WorkerPlugin
from stoq import Payload, PayloadMeta, ExtractedPayload, RequestMeta, WorkerResponse


class OlePlugin(WorkerPlugin):
    def scan(self, payload: Payload, request_meta: RequestMeta) -> WorkerResponse:
        extracted = []
        errors = []
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
                errors.append(str(err))
        return WorkerResponse(extracted=extracted, errors=errors)

