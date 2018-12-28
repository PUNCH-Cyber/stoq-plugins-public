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
Publish and Consume messages from a Kafka Server

"""

import json
from queue import Queue
from configparser import ConfigParser
from typing import Dict, List, Optional, Union
from kafka import KafkaConsumer, KafkaProducer

from stoq import helpers
from stoq.data_classes import StoqResponse
from stoq.plugins import ConnectorPlugin, ProviderPlugin


class KafkaPlugin(ConnectorPlugin, ProviderPlugin):
    def __init__(self, config: ConfigParser, plugin_opts: Optional[Dict]) -> None:
        super().__init__(config, plugin_opts)
        self.servers: Union[List[str], None] = None
        self.group: str = 'stoq'
        self.topic: str = 'stoq'
        self.publish_archive: bool = True
        self.retries: int = 5
        self.producer = None

        if plugin_opts and 'servers' in plugin_opts:
            self.servers = plugin_opts['servers']
        elif config.has_option('options', 'servers'):
            self.servers = [
                s.strip() for s in config.get('options', 'servers').split(',')
            ]

        if plugin_opts and "group" in plugin_opts:
            self.group = plugin_opts["group"]
        elif config.has_option("options", "group"):
            self.group = config.get("options", "group")

        if plugin_opts and "topic" in plugin_opts:
            self.topic = plugin_opts["topic"]
        elif config.has_option("options", "topic"):
            self.topic = config.get("options", "topic")

        if plugin_opts and "publish_archive" in plugin_opts:
            self.publish_archive = bool(plugin_opts["publish_archive"])
        elif config.has_option("options", "publish_archive"):
            self.publish_archive = config.getboolean("options", "publish_archive")

        if plugin_opts and "retries" in plugin_opts:
            self.retries = int(plugin_opts["retries"])
        elif config.has_option("options", "retries"):
            self.retries = config.getint("options", "retries")

    def save(self, response: StoqResponse) -> None:
        """
        Save results or ArchiverResponse to Kafka

        """
        self._connect()
        if self.publish_archive:
            msgs: List[str] = []
            for result in response.results:
                msgs = [{k: v} for k, v in result.archivers.items()]
            for msg in msgs:
                self.producer.send(self.topic, helpers.dumps(msg).encode())
        else:
            self.producer.send(self.topic, str(response).encode())

    def ingest(self, queue: Queue) -> None:
        consumer = KafkaConsumer(
            self.topic,
            group_id=self.group,
            auto_offset_reset='earliest',
            bootstrap_servers=self.servers,
        )
        print(f'Monitoring {self.topic} topic for messages...')
        for message in consumer:
            queue.put(json.loads(message.value))

    def _connect(self) -> None:
        """
        Connect to Kafka to publish a message

        """
        if not self.producer:
            self.producer = KafkaProducer(
                bootstrap_servers=self.servers, retries=self.retries
            )
