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

Publish and Consume messages from a Kafka Server

"""

from kafka import KafkaConsumer, KafkaProducer

from stoq.plugins import StoqSourcePlugin


class KafkaSource(StoqSourcePlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):
        self.stoq = stoq

        super().activate()

        self.producer = None

    def ingest(self):
        """
        Monitor Kafka for messages

        """

        # Define our Kafka topic
        topic = self.stoq.worker.name

        # If this is an error message, let's make sure our topic
        # has "-errors" affixed to it
        if self.stoq.worker.error_queue is True:
            topic = topic + "-errors".strip()

        consumer = KafkaConsumer(topic,
                                 group_id=self.group,
                                 auto_offset_reset='earliest',
                                 bootstrap_servers=self.servers_list)

        self.log.info("Monitoring {} topic for messages...".format(topic))

        for message in consumer:
            # Setup the amqp message for parsing
            msg = self.stoq.loads(message.value)

            # Send the message to the worker
            self.stoq.worker.multiprocess_put(**msg)

    def producer_connect(self):
        """
        Connect to Kafka to publish a message

        """
        self.producer = KafkaProducer(bootstrap_servers=self.servers_list,
                                      retries=self.retries)

    def producer_release(self):
        """
        Release AMQP connection used for publishing

        """
        return self.producer.close()

    def publish(self, msg, topic, err=False):
        """
        Publish a message to Kafka

        :param dict msg: Message to be published
        :param str topic: Topic to be used, should be name of worker
        :param bool err: Define whether we should process error topic

        """

        # Make sure we have a valid connection to RabbitMQ
        if not self.producer:
            self.producer_connect()

        # If this is an error message, let's make sure our queue
        # has "-errors" affixed to it
        if err:
            topic = topic + "-errors".strip()

        try:
            self.producer.send(topic, self.stoq.dumps(msg).encode())
        except:
            self.log.error("Unable to publish message to kafka server: {}".format(msg))
