#   Copyright 2014-2018 PUNCH Cyber Analytics Group
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
from queue import Queue
from google.cloud import pubsub
from typing import Dict, Optional
from configparser import ConfigParser
from google.api_core.exceptions import AlreadyExists

from stoq.plugins import ConnectorPlugin, ProviderPlugin, ArchiverPlugin
from stoq.data_classes import StoqResponse, Payload, RequestMeta, ArchiverResponse


class PubSubPlugin(ArchiverPlugin, ConnectorPlugin, ProviderPlugin):
    def __init__(self, config: ConfigParser, plugin_opts: Optional[Dict]) -> None:
        super().__init__(config, plugin_opts)

        self.project_id = None
        self.max_messages = 10
        self.publish_archive = True
        self.archiver_topic = None
        self.provider_topic = None
        self.connector_topic = None
        self.publish_client = None
        self.ingest_client = None

        if plugin_opts and 'project_id' in plugin_opts:
            self.project_id = plugin_opts['project_id']
        elif config.has_option('options', 'project_id'):
            self.project_id = config.get('options', 'project_id')

        if plugin_opts and "max_messages" in plugin_opts:
            self.max_messages = int(plugin_opts["max_messages"])
        elif config.has_option("options", "max_messages"):
            self.max_messages = int(config.get("options", "max_messages"))

        if plugin_opts and "publish_archive" in plugin_opts:
            self.publish_archive = bool(plugin_opts["publish_archive"])
        elif config.has_option("options", "publish_archive"):
            self.publish_archive = bool(config.get("options", "publish_archive"))

        if plugin_opts and "archiver_topic" in plugin_opts:
            self.archiver_topic = plugin_opts["archiver_topic"]
        elif config.has_option("options", "archiver_topic"):
            self.archiver_topic = config.get("options", "archiver_topic")

        if plugin_opts and "provider_topic" in plugin_opts:
            self.provider_topic = plugin_opts["provider_topic"]
        elif config.has_option("options", "provider_topic"):
            self.provider_topic = config.get("options", "provider_topic")

        if plugin_opts and "provider_subscription" in plugin_opts:
            self.provider_subscription = plugin_opts["provider_subscription"]
        elif config.has_option("options", "connector_subscription"):
            self.provider_subscription = config.get("options", "provider_subscription")

        if plugin_opts and "connector_topic" in plugin_opts:
            self.connector_topic = plugin_opts["connector_topic"]
        elif config.has_option("options", "connector_topic"):
            self.connector_topic = config.get("options", "connector_topic")

    def archive(
        self, payload: Payload, request_meta: RequestMeta
    ) -> Optional[ArchiverResponse]:
        topic = f'projects/{self.project_id}/topics/{self.archiver_topic}'
        self._publish_connect(topic)
        future = self.publish_client.publish(topic, str(payload.payload_meta).encode())
        return ArchiverResponse({'msg_id': future.result()})

    def save(self, response: StoqResponse) -> None:
        """
        Save results or ArchiverResponse to Pub/Sub

        """
        topic = f'projects/{self.project_id}/topics/{self.connector_topic}'
        self._publish_connect(topic)
        if self.publish_archive:
            msgs = [{k: v} for k, v in response.results.archivers.items()]
            for msg in msgs:
                self.publish_client.publish(topic, json.dumps(msg).encode())
        else:
            self.publish_client.publish(topic, str(response).encode())

    def ingest(self, queue: Queue) -> None:
        topic = f'projects/{self.project_id}/topics/{self.provider_topic}'
        subscription = (
            f'projects/{self.project_id}/subscriptions/{self.provider_subscription}'
        )
        self._ingest_connect(subscription, topic)
        print(f'Monitoring {subscription} subscription for messages...')
        while True:
            messages = self.ingest_client.pull(
                subscription, max_messages=self.max_messages, return_immediately=False
            )
            for msg in messages.received_messages:
                queue.put(json.loads(msg.message.data.decode()))
                msg.ack_id

    def _publish_connect(self, topic: str) -> None:
        if not self.publish_client:
            self.publish_client = pubsub.PublisherClient()
            try:
                self.publish_client.create_topic(topic)
            except AlreadyExists:
                pass

    def _ingest_connect(self, subscription: str, topic: str) -> None:
        self._publish_connect(topic)
        if not self.ingest_client:
            self.ingest_client = pubsub.SubscriberClient()
            try:
                self.ingest_client.create_subscription(subscription, topic)
            except AlreadyExists:
                pass
