#   Copyright 2014-present PUNCH Cyber Analytics Group
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

import json
from asyncio import Queue
from collections import ChainMap
from typing import Dict, Optional
from base64 import b64encode, b64decode
from kafka import KafkaConsumer, KafkaProducer

from stoq.helpers import StoqConfigParser, dumps
from stoq.plugins import ArchiverPlugin, ConnectorPlugin, ProviderPlugin
from stoq.data_classes import (
    ArchiverResponse,
    Payload,
    RequestMeta,
    PayloadMeta,
    StoqResponse,
)


class KafkaPlugin(ArchiverPlugin, ConnectorPlugin, ProviderPlugin):
    def __init__(self, config: StoqConfigParser) -> None:
        super().__init__(config)
        self.producer = None

        self.servers = config.getlist('options', 'servers', fallback=['127.0.0.1:9092'])
        self.group = config.get('options', 'group', fallback='stoq')
        self.topic = config.get('options', 'topic', fallback="stoq")
        self.publish_archive = config.getboolean(
            'options', 'publish_archive', fallback=True
        )
        self.retries = config.getint('options', 'retries', fallback=5)
        self.session_timeout_ms = config.getint(
            'options', 'session_timeout_ms', fallback=15000
        )
        self.heartbeat_interval_ms = config.getint(
            'options', 'heartbeat_interval_ms', fallback=5000
        )

    async def archive(
        self, payload: Payload, request: Request
    ) -> Optional[ArchiverResponse]:
        """
        Archive Payload object to Kafka queue

        """
        self._connect()
        msg = {
            '_is_payload': True,
            '_content': b64encode(payload.content),
            '_payload_meta': payload.payload_meta.extra_data,
            '_request_meta': request_meta,
        }
        self.producer.send(self.topic, helpers.dumps(msg).encode())
        self.producer.flush()
        return ArchiverResponse()

    async def save(self, response: StoqResponse) -> None:
        """
        Save results or ArchiverResponse to Kafka

        Either the full `StoqResponse` will be saved to the queue, or
        each individual payload that was archived by another archiver
        plugin. If it is an archived payload from a separate plugin,
        only the metadata produced from the archiver plugin will be
        sent to the queue, not the payload itself.

        """
        self._connect()
        if self.publish_archive:
            for result in response.results:
                for archiver, meta in result.archivers.items():
                    # Construct a message that includes the original metadata
                    # associated with the payload.
                    r = {
                        archiver: dict(
                            ChainMap(
                                meta,
                                result.payload_meta.extra_data,
                                {'request_meta': response.request_meta},
                            )
                        )
                    }
                    self.producer.send(self.topic, helpers.dumps(r).encode())
        else:
            self.producer.send(self.topic, str(response).encode())
        self.producer.flush()

    async def ingest(self, queue: Queue) -> None:
        consumer = KafkaConsumer(
            self.topic,
            group_id=self.group,
            auto_offset_reset='earliest',
            bootstrap_servers=self.servers,
            heartbeat_interval_ms=self.heartbeat_interval_ms,
            session_timeout_ms=self.session_timeout_ms,
        )
        self.log.info(f'Monitoring {self.topic} topic for messages...')
        for message in consumer:
            msg = json.loads(message.value)
            if msg.get('_is_payload'):
                # This message is a payload that was placed on the queue
                # from the kafka-queue archiver plugin
                extra_data = msg['_payload_meta']
                extra_data['request_meta'] = msg['_request_meta']
                meta = PayloadMeta(extra_data=extra_data)
                payload = Payload(content=b64decode(msg['_content']), payload_meta=meta)
                queue.put(payload)
            else:
                queue.put(msg)

    def _connect(self) -> None:
        """
        Connect to Kafka to publish a message

        """
        if not self.producer:
            self.producer = KafkaProducer(
                bootstrap_servers=self.servers, retries=self.retries
            )
