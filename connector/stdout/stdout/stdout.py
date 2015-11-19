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

Sends content to STDOUT

"""

from stoq.plugins import StoqConnectorPlugin


class StdoutConnector(StoqConnectorPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):
        self.stoq = stoq
        super().activate()

    def save(self, payload, **kwargs):
        """
        Print results to STDOUT

        :param bytes payload: Content to be printed to STDOUT
        :param **kwargs kwargs: Additional attributes (unused)

        """
        if type(payload) == dict:
            print(self.stoq.dumps(payload, compactly=False))
        else:
            print(payload)
