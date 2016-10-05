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

Carve OLE streams within Microsoft Office Documents

"""

import olefile

from io import BytesIO

from stoq.plugins import StoqCarverPlugin


class OLECarver(StoqCarverPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):
        self.stoq = stoq

        super().activate()

    def carve(self, payload, **kwargs):
        """
        Carve OLE streams

        :param bytes payload: OLE Payload to be parsed
        :param **kwargs kwargs: Additional attributes (unused)

        :returns: Carved OLE streams
        :rtype: list of tuples

        """

        results = None

        file_object = BytesIO(payload)
        try:
            ole_object = olefile.OleFileIO(file_object)
        except OSError:
            return results

        streams = ole_object.listdir()
        for stream in streams:
            try:
                stream_buffer = ole_object.openstream(stream).read()

                # Check to see if we have a buffer
                if stream_buffer:
                    # Looks like our first stream identified, let's make sure
                    # the results are in a list
                    if not results:
                        results = []

                    # Save the results as a set() within a list
                    meta = {'stream': streams.index(stream),
                            'name': stream[0],
                            'size': len(stream_buffer)}
                    results.append((meta, stream_buffer))

                    self.log.info("Carved OLE stream {}[{}] ({} bytes)".format(meta['name'],
                                                                               meta['stream'],
                                                                               meta['size']))
            except:
                pass

        return results
