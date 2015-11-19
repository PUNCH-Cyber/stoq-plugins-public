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

Upload content to a Tika server for automated text extraction

"""

from stoq.plugins import StoqReaderPlugin


class TikaReader(StoqReaderPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):
        self.stoq = stoq
        super().activate()

    def read(self, payload, **kwargs):
        """
        Leverage Apache Tika to read file (e.g., PDF, RTF, MS Office, etc.)
        and extract text

        :param bytes payload : Content to be sent to Tika server
        :param **kwargs kwargs: Additional attributes (unused)

        :returns: Extracted content of payload
        :rtype: bytes

        """
        return self.stoq.put_file(self.url, data=payload)
