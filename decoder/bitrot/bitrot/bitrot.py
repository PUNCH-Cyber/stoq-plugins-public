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

Bitwise rotation of a payload

"""

from stoq.plugins import StoqDecoderPlugin


class BitwiseRotateDecoder(StoqDecoderPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):
        self.stoq = stoq

        super().activate()

    def decode(self, payload, **kwargs):
        """
        Bitwise rotation of a payload

        :param bytes payload: Payload to be decoded
        :param **kwargs direction: left or right rotation of bits. Defaults
                                   to right.
        :param **kwargs bits: Defaults to 4 for nibble swapping.
                              Valid range is 0 - 8.

        :returns: Bitwise rotated payload
        :rtype: list of tuples

        """

        try:
            if 'bits' in kwargs:
                bits = kwargs['bits']
            else:
                bits = 4

            if 'direction' in kwargs:
                direction = kwargs['direction'].lower()
            else:
                direction = 'right'

            # Ensure rotation value is between 0 and 8
            if (bits < 0) or (bits > 8):
                raise ValueError('Rotation out of bounds (1-8)')

            payload = self.to_bytearray(payload)
            payload_length = len(payload)

            for index in range(payload_length):
                byte_value = payload[index]
                if direction == 'left':
                    payload[index] = (byte_value << bits | byte_value >> (8 - bits)) & 0xFF
                else:
                    payload[index] = (byte_value >> bits | byte_value << (8 - bits)) & 0xFF

            # Define the metadata we want to return
            meta = {}
            meta['size'] = payload_length
            meta['bits'] = bits
            meta['direction'] = direction

            # Return the results as a list of tuples
            return [(meta, payload)]

        except Exception as err:
            self.log.error("Unable to bitwise rotate payload: {}".format(str(err)))
            return None
