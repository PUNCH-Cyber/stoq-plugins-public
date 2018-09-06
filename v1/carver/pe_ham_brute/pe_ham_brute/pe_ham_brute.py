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

Search for n-grams for use as XOR key and leverages hamming distance to
determine key size.

Credits
=======

Ported to stoQ plugin and python3 from Alexander Hanel's pe_ham_brute.py script
(https://bitbucket.org/snippets/Alexander_Hanel/94p4R)

"""

import re
import pefile

from io import BytesIO
from itertools import cycle
from collections import Counter

from stoq.plugins import StoqCarverPlugin


class PEHamBruteCarver(StoqCarverPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):
        self.stoq = stoq

        super().activate()

        # Make sure these are bytes
        self.headers = self.headers.encode()

    def carve(self, payload, **kwargs):
        """
        Search for n-grams for use as XOR key and leverages hamming distance to
        determine key size.

        :param bytes payload: Payload to be analyzed
        :param int key_length: Length of key

        :returns: Carved PE Payload
        :rtype: list of tuples

        """

        results = None

        key_length = kwargs.get('key_length', self.key_length)

        key_sizes = self.key_len(payload, int(key_length))

        for temp_sz in key_sizes:
            size = temp_sz[1]
            substr_counter = Counter(payload[i: i + size] for i in range(len(payload) - size))

            sub_count = substr_counter.most_common(32)

            for temp in sub_count:
                key, count = temp
                if count == 1:
                    break

                possible_pe = self.xor_mb(payload, key)
                carved_pe = self.pe_carve(possible_pe)

                if carved_pe:
                    if results is None:
                        results = []

                    meta = {}
                    meta['key'] = key.decode()
                    meta['size'] = len(carved_pe)
                    results.append((meta, carved_pe))

        return results

    def xor_mb(self, payload, key):
        return bytearray([(m_byte ^ k_byte) for m_byte, k_byte in list(zip(payload, cycle(key)))])

    def hamming_distance(self, bytes_a, bytes_b):
        return sum(bin(i ^ j).count("1") for i, j in list(zip(bytearray(bytes_a), bytearray(bytes_b))))

    def key_len(self, message, key_size):
        """ returns [(dist, key_size),(dist, key_size)] """
        avg = []
        for k in range(2, key_size):
            hd = []
            for n in range(len(message) // k - 1):
                hd.append(int(self.hamming_distance(message[k * n: k * (n + 1)], message[k * (n + 1): k * (n * 2)]) / k))
            if hd:
                avg.append((sum(hd) / float(len(hd)), k))

        return sorted(avg)[:10]

    def pe_carve(self, possible_pe):
        payload = BytesIO(possible_pe)
        payload.seek(0)

        for start, end in self.carve_payload(self.headers, payload):
            payload.seek(start)
            try:
                pe = pefile.PE(data=payload.read())
                return pe.trim()
            except Exception:
                continue
        return None
