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

Publish and Consume messages from a Redis Server

"""

import redis

from stoq.plugins import StoqSourcePlugin


class RedisSource(StoqSourcePlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):
        self.stoq = stoq

        self.conn = None

        super().activate()

    def ingest(self, queue=None):
        """
        Monitor Redis for messages

        """

        if not self.conn:
            self.connect()

        if not queue:
            queue = self.stoq.worker.name

        # If this is an error message, let's make sure our topic
        # has "-errors" affixed to it
        if self.stoq.worker.error_queue is True:
            queue = queue + "-errors".strip()

        self.log.info("Monitoring {} queue for messages...".format(queue))

        while True:
            msg = self.conn.blpop(queue, timeout=0)
            msgid = msg[1].decode()

            payload = self.conn.get("{}_buf".format(msgid))
            meta = self.conn.get("{}_meta".format(msgid))
            meta = meta.decode()

            meta = self.stoq.loads(meta)

            # Send the message to the worker
            try:
                self.stoq.worker.start(payload, **meta)
            except Exception as err:
                self.log.critical(err, exc_info=True)
                self.conn.rpush("{}-errors".format(queue), msgid)
                return

            self.conn.delete("{}_buf".format(msgid))
            self.conn.delete("{}_meta".format(msgid))

    def connect(self):
        """
        Connect to Redis

        """
        self.conn = redis.StrictRedis(host=self.redis_host, port=self.redis_port)

    def publish(self, msg, queue, err=False, payload=None, **kwargs):
        """
        Publish a message to Redis

        :param dict msg: Message to be published
        :param str topic: Queue to be used, should be name of worker
        :param bool err: Define whether we should process error queue

        """

        # Make sure we have a valid connection to RabbitMQ
        if not self.conn:
            self.connect()

        # If this is an error message, let's make sure our queue
        # has "-errors" affixed to it
        if err:
            queue = queue + "-errors".strip()

        try:
            msgid = msg['uuid'][0]

            # Keeping the naming structure inline with the Suricata Redis branch from LMCO
            # https://github.com/lmco/suricata/tree/file_extract_redis_prototype_v1
            msg = self.stoq.dumps(msg, compactly=True)
            self.conn.set("{}_meta".format(msgid), msg)
            self.conn.set("{}_buf".format(msgid), payload)

            # Finally, publish the id to the queue that workers are monitoring
            self.conn.rpush(queue, msgid)

        except:
            self.log.error("Unable to publish message to Redis server: {}".format(msg))
