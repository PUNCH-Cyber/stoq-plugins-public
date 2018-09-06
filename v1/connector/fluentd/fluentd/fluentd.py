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

Sends content to a fluentd server

"""

from fluent.sender import FluentSender

from stoq.plugins import StoqConnectorPlugin


class FluentdConnector(StoqConnectorPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):
        self.stoq = stoq
        super().activate()

    def save(self, payload, archive=False, **kwargs):
        """
        Save results to fluentd logger

        :param bytes payload: Content to be sent to fluentd
        :param **kwargs index: Index name to save content to

        """

        # Define the index name, if available. Will default to the plugin name
        index = kwargs.get('index', self.parentname)

        for save_attempt in range(3):
            try:
                self.sender.emit(index, payload)
            except AttributeError:
                self.connect()

        super().save()

    def connect(self, tag=None):
        """
        Connect to a fluentd logger

        """

        if not tag:
            tag = self.tag

        timeout = float(self.timeout)
        port = int(self.port)
        buffer_max = int(self.buffer_max)

        self.sender = FluentSender(tag, self.host, port, buffer_max, timeout)

    def disconnect(self):
        """
        Disconnect to a fluentd logger

        """
        self.sender._close()
