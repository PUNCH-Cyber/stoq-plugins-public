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

Decode XOR encoded content

"""

from stoq.plugins import StoqDecoderPlugin


class XorDecoder(StoqDecoderPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):
        self.stoq = stoq

        super().activate()

    def decode(self, payload, **kwargs):
        """
        XOR decode content from provided payload

        :param bytes payload: Payload to be decoded
        :param str key: String of space-separated XOR keys
                        (i.e., "41 166 3") or list/tuple of xor values

        :returns: XOR decoded payload
        :rtype: list of tuples or None

        """

        try:
            byte_content = self.to_bytearray(payload)
            content_length = len(byte_content)

            if 'key' in kwargs:
                if type(kwargs['key']) is not (list, tuple):
                    xor_values = kwargs['key'].split(" ")
            else:
                self.log.error("No XOR key(s) provided.")
                return None

            last_rolling_index = len(xor_values) - 1
            current_rolling_index = 0

            for index in range(content_length):

                xor_value = xor_values[current_rolling_index]
                byte_content[index] ^= int(xor_value)

                if current_rolling_index < last_rolling_index:
                    current_rolling_index += 1
                else:
                    current_rolling_index = 0

            # Define the metadata we want to return
            meta = {}
            meta['size'] = content_length

            # Return the results as a list of tuples
            return [(meta, bytes(byte_content))]

        except Exception as err:
            self.log.warn("Unable to XOR payload: {}".format(str(err)))
            return None
