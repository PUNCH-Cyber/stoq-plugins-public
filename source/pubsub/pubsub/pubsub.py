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

Publish and Consume messages from Google's Pub/Sub Service

"""

from time import sleep
from google.cloud import pubsub
from google.cloud.pubsub.subscription import AutoAck

from stoq.plugins import StoqSourcePlugin


class PubsubSource(StoqSourcePlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):
        self.stoq = stoq
        self.conn = None

        # If no source_queue is defined, default to the name of the worker
        if self.stoq.worker.source_queue:
            self.topic = self.stoq.worker.source_queue
        else:
            self.topic = self.stoq.worker.name

        super().activate()

    def ingest(self):
        """
        Monitor Pub/Sub for messages

        """

        self._connect()

        subscription = self.conn.subscription(self.topic)

        if not subscription.exists():
            subscription.create()

        self.log.info("Monitoring {} subscription for messages...".format(self.topic))

        while True:
            try:
                with AutoAck(subscription, max_messages=int(self.max_messages)) as ack:
                    for ack_id, message in list(ack.items()):
                        try:
                            msg = message.data
                            kwargs = self.stoq.loads(msg.decode())

                            # Send the message to the worker
                            self.stoq.worker.multiprocess_put(**kwargs)
                        except Exception:
                            try:
                                del ack[ack_id]
                            except:
                                pass

            except Exception as err:
                self.log.warn("Unable to connect to Pub/Sub subscription: {}".format(err))
                sleep(1)

    def _connect(self, topic=None):
        """
        Connect to Pub/Sub

        :param str topic: Topic to use, default is worker name

        :returns: AMQP connection object for publishing
        :rtype: kombu.Connection object

        """
        pubsub_client = pubsub.Client()

        if not topic:
            topic = self.topic

        self.conn = pubsub_client.topic(topic)

        # Create topic if it does not exist
        if not self.conn.exists():
            self.conn.create()

    def publish(self, msg, topic, err=False, **kwargs):
        """
        Publish a message to Pub/Sub

        :param dict msg: Message to be published
        :param str topic: Topic to publish message to
        :param bool err: Unused

        """

        count = 0

        # Make sure we have a valid connection to Pub/Sub
        if not self.conn:
            self._connect(topic)

        msg = self.stoq.dumps(msg).encode()

        # Sometimes the session times out, let's attempt to connect up to 5
        # times.
        while True:
            try:
                message_id = self.conn.publish(msg)
                self.log.debug("Message {} published".format(message_id))
                break
            except Exception as err:
                # Make sure we don't end up in an infinite loop
                if count > 5:
                    self.log.error("Failed to publish message to {} skipping: {}".format(topic, err))
                    break

                self.log.warn("Unable to publish message, trying again...")
                sleep(1)
                count += 1
