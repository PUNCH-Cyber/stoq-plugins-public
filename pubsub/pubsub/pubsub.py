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

Interact with Google Cloud Pub/Sub

"""

import json
from asyncio import Queue
from google.cloud import pubsub
from typing import Dict, List, Optional
from google.api_core.exceptions import DeadlineExceeded

from stoq.helpers import StoqConfigParser
from stoq.plugins import ConnectorPlugin, ProviderPlugin, ArchiverPlugin
from stoq.data_classes import StoqResponse, Payload, Request, ArchiverResponse


class PubSubPlugin(ArchiverPlugin, ConnectorPlugin, ProviderPlugin):
    def __init__(self, config: StoqConfigParser) -> None:
        super().__init__(config)

        self.publish_client = None
        self.ingest_client = None
        self.project_id = config.get('options', 'project_id')
        self.max_messages = config.getint('options', 'max_messages', fallback=10)
        self.publish_archive = config.getboolean(
            'options', 'publish_archive', fallback=True
        )
        self.topic = config.get('options', 'topic', fallback='stoq')
        self.subscription = config.get('options', 'subscription', fallback='stoq')

    async def archive(
        self, payload: Payload, request: Request
    ) -> Optional[ArchiverResponse]:
        topic = f'projects/{self.project_id}/topics/{self.topic}'
        self._publish_connect(topic)
        future = self.publish_client.publish(
            topic, payload.content, meta=payload.payload_meta
        )
        return ArchiverResponse({'msg_id': future.result()})

    async def save(self, response: StoqResponse) -> None:
        """
        Save results or ArchiverResponse to Pub/Sub

        """
        topic = f'projects/{self.project_id}/topics/{self.topic}'
        self._publish_connect(topic)
        if self.publish_archive:
            msgs: List[Dict[str, str]] = []
            for result in response.results:
                msgs = [{k: v} for k, v in result.archivers.items()]
            for msg in msgs:
                self.publish_client.publish(topic, json.dumps(msg).encode())
        else:
            self.publish_client.publish(topic, str(response).encode())

    async def ingest(self, queue: Queue) -> None:
        topic = f'projects/{self.project_id}/topics/{self.topic}'
        subscription = f'projects/{self.project_id}/subscriptions/{self.subscription}'
        self._ingest_connect(subscription, topic)
        self.log.info(f'Monitoring {subscription} subscription for messages...')
        while True:
            try:
                messages = self.ingest_client.pull(
                    subscription,
                    max_messages=self.max_messages,
                    return_immediately=False,
                )
                for msg in messages.received_messages:
                    await queue.put(json.loads(msg.message.data.decode()))
                    self.ingest_client.acknowledge(subscription, [msg.ack_id])
            except DeadlineExceeded:
                self.log.debug(
                    f'Reconnecting to {subscription} subscription for messages...'
                )
                self._ingest_connect(subscription, topic)

    def _publish_connect(self, topic: str) -> None:
        if not self.publish_client:
            self.publish_client = pubsub.PublisherClient()

    def _ingest_connect(self, subscription: str, topic: str) -> None:
        self._publish_connect(topic)
        if not self.ingest_client:
            self.ingest_client = pubsub.SubscriberClient()
