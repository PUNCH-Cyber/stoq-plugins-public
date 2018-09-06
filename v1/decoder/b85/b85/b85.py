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

Decode base85 encoded content

"""

import base64

from stoq.plugins import StoqDecoderPlugin


class Base85Decoder(StoqDecoderPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):
        self.stoq = stoq

        super().activate()

    def decode(self, payload, **kwargs):
        """
        Base85 decode content from provided payload

        :param bytes payload: Payload to be decoded
        :param **kwargs kwargs: Additional attributes (unused)

        :returns: Base85 decoded content
        :rtype: list of tuples

        """

        try:
            # Decode our payload
            content = base64.b85decode(payload)

            # Define the metadata we want to return
            meta = {}
            meta['size'] = len(content)

            # Return the results as a list of tuples
            return [(meta, content)]

        except Exception as err:
            self.log.error("Unable to Base85 decode payload: {}".format(str(err)))
            return None
