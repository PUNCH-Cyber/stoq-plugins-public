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

Send results to a queuing system, such as RabbitMQ

"""

from stoq.plugins import StoqConnectorPlugin


class QueueConnector(StoqConnectorPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):
        self.stoq = stoq
        super().activate()

        # Activate the appropriate plugin so we can publish messages, if needed.
        self.queue = self.stoq.load_plugin(self.publisher, 'source')

    def save(self, payload, **kwargs):
        """
        Send results to a queuing system, such as RabbitMQ

        :param bytes payload: Message to be sent to RabbitMQ
        :param **kwargs index: Queue name to publish message into

        """

        if 'index' in kwargs:
            routing_key = kwargs['index']
        else:
            routing_key = "{}-{}".format(self.parentname, "results")

        if hasattr(self.queue, 'publish'):
            self.queue.publish(payload, routing_key)
        else:
            self.log.warn("{} does not support publishing!".format(self.publisher))
            return False

        return True
